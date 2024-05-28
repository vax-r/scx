#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

enum {
  FALLBACK_DSQ_ID = 0,
  MS_TO_NS = 1000LLU * 1000,
  TIMER_INTERVAL_NS = 1 * MS_TO_NS,
};

const volatile s32 central_cpu;
const volatile u32 nr_cpus = 1;    /* !0 for veristat, set during init */
const volatile u32 nr_cpu_ids = 1; /* !0 for veristat, set during init */
const volatile u64 slice_ns = SCX_SLICE_DFL;

bool timer_pinned = true;
u64 nr_total, nr_locals, nr_queued, nr_lost_pids;
u64 nr_timers, nr_dispatches, nr_mismatches, nr_retries;
u64 nr_overflows;

UEI_DEFINE(uei);

/* can't use percpu map due to bad lookups */
bool RESIZABLE_ARRAY(data, cpu_gimme_task);
u64 RESIZABLE_ARRAY(data, cpu_started_at);

struct randmigrate_timer {
  struct bpf_timer timer;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct randmigrate_timer);
} randmigrate_timer SEC(".maps");

s32 BPF_STRUCT_OPS(randmigrate_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags) {
  s32 cpu = bpf_get_prandom_u32() % nr_cpus;
  return cpu;
}

void BPF_STRUCT_OPS(randmigrate_enqueue, struct task_struct *p, u64 enq_flags) {
  __sync_fetch_and_add(&nr_total, 1);

  if ((p->flags & PF_KTHREAD) && p->nr_cpus_allowed == 1) {
    __sync_fetch_and_add(&nr_locals, 1);
    scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_INF,
                     enq_flags | SCX_ENQ_PREEMPT);
    return;
  }

  s32 cpu = bpf_get_prandom_u32() % nr_cpus;

  __sync_fetch_and_add(&nr_queued, 1);

  scx_bpf_dispatch(p, FALLBACK_DSQ_ID, SCX_SLICE_INF, enq_flags);

  if (!scx_bpf_task_running(p))
    scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
}

void BPF_STRUCT_OPS(randmigrate_dispatch, s32 cpu, struct task_struct *prev) {
  if (cpu == central_cpu) {

    __sync_fetch_and_add(&nr_dispatches, 1);

    if (scx_bpf_consume(FALLBACK_DSQ_ID))
      return;

    s32 wake_cpu = bpf_get_prandom_u32() % nr_cpus;
    scx_bpf_kick_cpu(wake_cpu, SCX_KICK_PREEMPT);
  }
}

void BPF_STRUCT_OPS(randmigrate_running, struct task_struct *p) { return; }

void BPF_STRUCT_OPS(randmigrate_stopping, struct task_struct *p,
                    bool runnable) {
  return;
}

int BPF_STRUCT_OPS_SLEEPABLE(randmigrate_init) {
  int ret;

  __COMPAT_scx_bpf_switch_all();
  ret = scx_bpf_create_dsq(FALLBACK_DSQ_ID, -1);
  return ret;
}

void BPF_STRUCT_OPS(randmigrate_exit, struct scx_exit_info *ei) {
  UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(randmigrate_ops,
               /*
                * We are offloading all scheduling decisions to the central CPU
                * and thus being the last task on a given CPU doesn't mean
                * anything special. Enqueue the last tasks like any other tasks.
                */
               .flags = SCX_OPS_ENQ_LAST,

               .select_cpu = (void *)randmigrate_select_cpu,
               .enqueue = (void *)randmigrate_enqueue,
               .dispatch = (void *)randmigrate_dispatch,
               .running = (void *)randmigrate_running,
               .stopping = (void *)randmigrate_stopping,
               .init = (void *)randmigrate_init,
               .exit = (void *)randmigrate_exit, .name = "randmigrate");
