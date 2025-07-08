from flask import Flask, request, jsonify, render_template, send_file
import pandas as pd
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '1'  # Nasconde messaggi INFO
from werkzeug.utils import secure_filename
import tempfile
from src.phishing_classifier import PhishingClassifier
import yaml
# Caricamento della configurazione
with open("configs/config.yaml", "r") as f:
    config = yaml.safe_load(f)

Classifier = PhishingClassifier()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'

# Crea la cartella uploads se non existe
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/predict_single_url', methods=['POST'])
def predict_single_url():
    """API per predire una singola URL"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL mancante nel payload JSON'}), 400
        
        url = data['url']
        prediction = Classifier.predict_url(config, url)
        
        return jsonify({
            'url': url,
            'error': prediction['error'],
            'rf_probability': prediction['rf_probability'],
            'bert_probability': prediction['bert_probability'],
            'cnn_probability': prediction['cnn_probability'],
            'ensemble_decision': prediction['ensemble_decision'],
            'is_phishing': prediction['is_phishing'],
            'status': 'success'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    ### ESEMPIO DI PREDIZIONE DA SINGOLO URL ###
    # {
    #    "url": "www.google.com"
    # }
    # Headers:
    # Content-Type: application/json

@app.route('/predict_urls', methods=['POST'])
def predict_urls():
    """API per predire una lista di URL (restituisce JSON)"""
    try:
        data = request.get_json()
        df = pd.DataFrame(data)
        predicted_df = Classifier.predict_urls_df(config, df)
        result = predicted_df.to_dict('records')
        
        return result
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    ### ESEMPIO DI PREDIZIONE DA LISTA DI URL ###
    # [{
    #    "url":"google.com"
    # },
    # {
    #    "url":"yahoo.com"
    # }]
    
    # Headers:
    # Content-Type: application/json

@app.route('/predict_from_filepath', methods=['POST'])
def predict_from_file():
    """API per predire URLs da file CSV (restituisce JSON)"""
    try:
        data = request.get_json()
        if not data or 'file_path' not in data:
            return jsonify({'error': 'Percorso file mancante nel payload JSON'}), 400
        
        file_path = data['file_path']
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File non trovato'}), 404
        
        # Carica il dataset e effettua le predizioni
        df = pd.read_csv(file_path)
        predicted_df = Classifier.predict_urls_df(config, df)
        
        #result = predicted_df.to_json(orient='records', force_ascii=False, lines= False)
            
        # Converte il DataFrame in JSON
        result = predicted_df.to_dict('records')
        
        return result
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    ### ESEMPIO DI PREDIZIONE DA Path del csv ###
    #{
    #    "file_path" : "C:\\Users\\fpalazzo\\Documents\\YoroiPhish\\data\\external\\top20.csv"
    #}
    # Headers:
    # Content-Type: application/json
@app.route('/upload_and_predict')
def upload_form():
    """Pagina HTML per upload file"""
    return render_template('upload.html')

@app.route('/upload_and_predict', methods=['POST'])
def upload_and_predict():
    """API per upload CSV e download predizioni"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Nessun file caricato'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Nessun file selezionato'}), 400
        
        if not file.filename.lower().endswith('.csv'):
            return jsonify({'error': 'Solo file CSV sono supportati'}), 400
        
        # Salva il file caricato
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Carica e predici
        df = pd.read_csv(filepath)
        predicted_df = Classifier.predict_urls_df(config, df)
        
        # Crea file temporaneo per il download
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
        predicted_df.to_csv(temp_file.name, index=False)
        temp_file.close()
        
        # Pulisci il file caricato
        os.remove(filepath)
        
        # Invia il file per il download
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=f'predicted_{filename}',
            mimetype='text/csv'
        )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)