# celery_worker.py
from celery import Celery
from src.phishing_classifier import PhishingClassifier
import pandas as pd
import yaml

# Caricamento configurazione
with open("configs/config.yaml", "r") as f:
    config = yaml.safe_load(f)

Classifier = PhishingClassifier()

# Configura Celery con Redis come broker
celery_app = Celery("yoroi_tasks", broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0")

@celery_app.task
def predict_from_csv_task(file_path):
    df = pd.read_csv(file_path)
    predicted_df = Classifier.predict_urls_df(config, df)
    output_path = file_path.replace(".csv", "_predicted.csv")
    predicted_df.to_csv(output_path, index=False)
    return output_path

@celery_app.task
def predict_single_url_task(config_dict, url):
    clf = PhishingClassifier()
    return clf.predict_url(config_dict, url)

@celery_app.task
def test_task():
    return "ok"
