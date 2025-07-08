# app.py
from flask import Flask, request, jsonify, render_template, send_file
import pandas as pd
import os
import tempfile
from werkzeug.utils import secure_filename
from celery.result import AsyncResult
from celery_worker import predict_from_csv_task, celery_app, predict_single_url_task, test_task
from src.phishing_classifier import PhishingClassifier
import yaml

# Configurazioni iniziali
with open("configs/config.yaml", "r") as f:
    config = yaml.safe_load(f)

Classifier = PhishingClassifier()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/test', methods=['GET'])
def test():
    """Endpoint di test per verificare che il server sia attivo."""
    try:
        result = test_task.delay()
        return jsonify({'task_id': result.id, 'status': 'In esecuzione', 'message': 'Test task avviato.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/predict_single_url', methods=['POST'])
def predict_single_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL mancante nel payload'}), 400
        
        url = data['url']
        task = predict_single_url_task.delay(config, url)
        
        return jsonify({
            'task_id': task.id,
            'status': 'In esecuzione',
            'message': 'Predizione avviata in background.'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/predict_urls', methods=['POST'])
def predict_urls():
    try:
        data = request.get_json()
        df = pd.DataFrame(data)
        predicted_df = Classifier.predict_urls_df(config, df)
        return predicted_df.to_dict('records')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/predict_from_filepath', methods=['POST'])
def predict_from_file():
    try:
        data = request.get_json()
        if not data or 'file_path' not in data:
            return jsonify({'error': 'Percorso file mancante'}), 400

        file_path = data['file_path']
        if not os.path.exists(file_path):
            return jsonify({'error': 'File non trovato'}), 404

        task = predict_from_csv_task.delay(file_path)
        return jsonify({
            'task_id': task.id,
            'status': 'In esecuzione',
            'message': 'Predizione avviata in background.'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/task_status/<task_id>', methods=['GET'])
def get_status(task_id):
    task_result = AsyncResult(task_id, app=celery_app)
    response = {
        'task_id': task_id,
        'status': task_result.status
    }
    if task_result.status == 'SUCCESS':
        response['output_file'] = task_result.result
    return jsonify(response)

@app.route('/upload_and_predict')
def upload_form():
    return render_template('upload.html')

@app.route('/upload_and_predict', methods=['POST'])
def upload_and_predict():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Nessun file caricato'}), 400

        file = request.files['file']
        if file.filename == '' or not file.filename.lower().endswith('.csv'):
            return jsonify({'error': 'File non valido'}), 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        task = predict_from_csv_task.delay(filepath)
        return jsonify({'task_id': task.id, 'status': 'in background'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
