import os
import joblib
import tensorflow as tf
from transformers import TFBertForSequenceClassification
import numpy as np
import uvicorn
from fastapi import FastAPI, UploadFile, File
import pandas as pd
from pydantic import BaseModel
from decision_engine import load_config, get_model_predictions, classify_sites

# Inizializzazione FastAPI
app = FastAPI(title="Phishing Detector API")

# Caricamento configurazione e modelli
config = load_config(config)
models = {
    "random_forest": joblib.load("models/random_forest.pkl"),
    "xgboost": joblib.load("models/xgboost.pkl"),
    "cnn": tf.keras.models.load_model("models/cnn.h5"),
    "bert": TFBertForSequenceClassification.from_pretrained("models/bert"),
}

class InputData(BaseModel):
    text: str = None
    url_features: list = []
    image: UploadFile = None

@app.post("/predict")
async def predict(data: InputData):
    """
    API per ricevere input e restituire la classificazione del sito.
    """
    text_inputs = tokenizer(data.text, padding=True, truncation=True, max_length=512, return_tensors="tf") if data.text else None
    url_features = np.array(data.url_features).reshape(1, -1) if data.url_features else None
    img_array = None  # Qui si potrebbe processare l'immagine se necessario

    predictions = get_model_predictions(models, url_features, img_array, text_inputs)
    classification = classify_sites(predictions, config["decision_engine"]["weights"], config["decision_engine"]["threshold"])

    return {"prediction": int(classification)}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
