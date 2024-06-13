import tensorflow as tf
from tensorflow import keras
model = keras.models.load_model('model_stress_model.h5')
model.export('model_path')