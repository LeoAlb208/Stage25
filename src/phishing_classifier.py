import json
import os
import sys
import joblib
import numpy as np
import pandas as pd
from src.parsing import process_directory
import tensorflow as tf
from src.bert_model import BertPhishingClassifier
from src.data_collection import download_temp_page
from src.test_screenshot_capture import capture_single_screenshot, batch_capture_screenshots_parallel
from src.train_csv_creation import create_test_csv
from src.clean_text_data import clean_text_features
import shutil
from urllib.parse import urlparse

class PhishingClassifier:
    def __init__(self):
        """
        Initialize the phishing classifier
        """
        # Carica il modello Random Forest
        self.rf_model = joblib.load('models/random_forest.pkl')
        print("✅ Modello Random Forest caricato con successo!")
        
        self.bert_model = BertPhishingClassifier.from_pretrained("models/bert")
        print("✅ Modello Bert caricato con successo!")

        cnn_model_path = os.path.join('models', 'cnn', 'phishing_cnn_model.h5')
        self.cnn_model = tf.keras.models.load_model(cnn_model_path)
        print(f"✅ CNN model loaded from {cnn_model_path}")
        
        self.ensemble_config_path = os.path.join('models','ensemble', 'ensemble_model_config.json')
        
        
    def predict_url(self, config, url: str, verbose=True):
        """
        Analyze a URL by downloading its content, extracting features, and making a prediction
        using an ensemble of models (Random Forest, BERT, and CNN)
        
        Args:
            url (str): URL to analyze
            config: Configuration for download
            verbose (bool): Whether to print detailed information during processing
            
        Returns:
            dict: Dictionary containing prediction probabilities, ensemble decision and error information
        """
        # Load ensemble configuration
        try:
            with open(self.ensemble_config_path, 'r') as f:
                loaded_ensemble_config = json.load(f)
            
            # Get ensemble parameters
            avg_threshold = loaded_ensemble_config['ensemble_parameters']['avg_prediction_threshold']
            
            # Parameters for Rule 1 (RF direct phishing)
            rule1_rf_thresh = loaded_ensemble_config['ensemble_parameters']['rules']['rf_direct_phishing']['rf_threshold']
            
            # Parameters for Rule 2 (CNN & RF phishing)
            rule2_cnn_thresh = loaded_ensemble_config['ensemble_parameters']['rules']['cnn_rf_phishing']['cnn_threshold']
            rule2_rf_thresh = loaded_ensemble_config['ensemble_parameters']['rules']['cnn_rf_phishing']['rf_threshold']
            
            # Parameters for Rule 3 (BERT & RF phishing)
            rule3_bert_thresh = loaded_ensemble_config['ensemble_parameters']['rules']['bert_rf_phishing']['bert_threshold'] 
            rule3_rf_thresh = loaded_ensemble_config['ensemble_parameters']['rules']['bert_rf_phishing']['rf_threshold']
            
            if verbose:
                print("✅ Ensemble configuration loaded successfully")
        except Exception as e:
            if verbose:
                print(f"⚠️ Error loading ensemble configuration: {e}. Using default thresholds.")
            # Default ensemble parameters if loading fails
            avg_threshold = 0.6
            rule1_rf_thresh = 0.8
            rule2_cnn_thresh = 0.99
            rule2_rf_thresh = 0.5
            rule3_bert_thresh = 0.99
            rule3_rf_thresh = 0.5
        
        def preprocess_image(img_path, target_size=(224, 224)):
            try:
                img = tf.keras.preprocessing.image.load_img(img_path, target_size=target_size)
                img_array = tf.keras.preprocessing.image.img_to_array(img)
                img_array = np.expand_dims(img_array, axis=0) # Create batch axis
                img_array = img_array / 255.0 # Rescale
                return img_array
            except Exception as e:
                print(f"⚠️ Error processing image {img_path}: {e}")
                return None
                
        # Create necessary directories if they don't exist
        temp_dir = os.path.join(os.getcwd(), 'temp')
        html_dir = os.path.join(temp_dir, 'html')
        results_dir = os.path.join(temp_dir, 'results')
        screenshot_dir = os.path.join(temp_dir, 'screenshot')

        # Create directories if they don't exist
        for directory in [temp_dir, html_dir, results_dir, screenshot_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)
        # Download the page - handle failure case
        try:
            url, file_path = download_temp_page(url, config, verbose=verbose)
        except Exception as e:
            if verbose:
                print(f"⚠️ Error downloading page: {e}")
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                if verbose:
                    print(f"✅ Directory temporanea {temp_dir} eliminata")
            file_path = None
        if file_path == "":
            if verbose:
                print(f"❌ Failed to download page from {url}")
            # Clean up any created directories
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except Exception:
                pass
            # Return error information
            return {
                "error": True,
                "message": f"Failed to download page from {url}",
                "rf_probability": None,
                "bert_probability": None,
                "cnn_probability": None,
                "avarage_probability": None,
                "ensemble_decision": False,
                "is_phishing": None
            }
            
        if verbose:
            print(f"Pagina scaricata in {file_path}")
        
        # Screenshot capture flag
        screenshot_captured = False
        
        if capture_single_screenshot(url, screenshot_dir, results_csv_path=os.path.join(results_dir, 'screenshot.csv'), verbose=verbose):
            if verbose:
                print(f"Screenshot salvato in {screenshot_dir}")
            screenshot_captured = True
        else:
            if verbose:
                print(f"Errore nella cattura di {url}")
        
        try:
            # Dataset per predizione con Random Forest
            rf_df = create_test_csv(os.path.join(results_dir, 'temp.csv'), os.path.join(results_dir, 'parsed_temp.csv'), verbose=verbose)
            if verbose:
                print("Dataset per Random Forest creato")
            
            # Output paths
            test_text = os.path.join(results_dir, "html_test_text.csv")
            test_numeric = os.path.join(results_dir, "html_test_numeric.csv")
            
            # Eseguiamo il parsing
            _, test_df_text = process_directory(
                html_dir,
                test_numeric,
                test_text)
            if verbose:
                print("Parsing HTML completato")
                
            bert_text = clean_text_features(test_df_text)
            # Dataset per predizione con Bert
            bert_df = bert_text["text_combined"].tolist()
            if verbose:
                print("Feature per BERT estratte")
            
            # Dataset per predizione con CNN - solo se lo screenshot è stato catturato
            cnn_image_paths = []
            cnn_prob = None
            if screenshot_captured:
                cnn_test_df = pd.read_csv(os.path.join(results_dir, 'screenshot.csv'))
                cnn_image_paths = cnn_test_df['screenshot_path'].tolist()
                for i, img_path in enumerate(cnn_image_paths):
                    processed_img = preprocess_image(img_path)
                    if processed_img is not None:
                        cnn_prob = self.cnn_model.predict(processed_img, verbose=0)[0][0] # Get probability for the single image
                        if verbose:
                            print("Immagine per CNN elaborata con successo")
            
            #Predizione rf
            rf_probs = self.rf_model.predict_proba(rf_df.drop('is_phishing', axis=1))[:, 1]
            
            #Predizione bert
            bert_probs = self.bert_model.predict(bert_df)['phishing_probability']
            
            # Print the extracted probabilities
            if verbose:
                print(f"Probabilità Random Forest: {rf_probs[0]:.4f}")
                print(f"Probabilità BERT: {bert_probs[0]:.4f}")
                if screenshot_captured and cnn_prob is not None:
                    print(f"Probabilità CNN: {cnn_prob:.4f}")
                else:
                    print("Probabilità CNN: Non disponibile (screenshot non catturato o elaborazione fallita)")

            # Apply ensemble logic
            rf_prob = float(rf_probs[0])
            bert_prob = float(bert_probs[0])
            cnn_prob = float(cnn_prob) if screenshot_captured and cnn_prob is not None else None
            
            # Initialize ensemble decision as False
            is_phishing = False
            
            # Apply rules based on ensemble configuration
            valid_models_count = 3 if cnn_prob is not None else 2
            
            # Rule 1: If RF probability exceeds its threshold, classify as phishing
            if rf_prob >= rule1_rf_thresh:
                is_phishing = True
                rule_applied = "Rule 1: RF direct phishing"
            
            # Rule 2: If CNN and RF both exceed their thresholds, classify as phishing
            elif cnn_prob is not None and cnn_prob >= rule2_cnn_thresh and rf_prob >= rule2_rf_thresh:
                is_phishing = True
                rule_applied = "Rule 2: CNN & RF phishing"
            
            # Rule 3: If BERT and RF both exceed their thresholds, classify as phishing
            elif bert_prob >= rule3_bert_thresh and rf_prob >= rule3_rf_thresh:
                is_phishing = True
                rule_applied = "Rule 3: BERT & RF phishing"
            
            # Average probability calculation (exclude CNN if not available)
            else:
                # Calculate average of available model probabilities
                avg_prob = 0
                if valid_models_count == 3:
                    avg_prob = (rf_prob + bert_prob + cnn_prob) / 3
                else:
                    avg_prob = (rf_prob + bert_prob) / 2
                    
                # Apply average threshold
                if avg_prob >= avg_threshold:
                    is_phishing = True
                    rule_applied = f"Average probability ({avg_prob:.4f}) exceeds threshold ({avg_threshold})"
                else:
                    rule_applied = f"Average probability ({avg_prob:.4f}) below threshold ({avg_threshold})"
            
            if verbose:
                print(f"Ensemble decision: {'Phishing' if is_phishing else 'Legitimate'}")
                print(f"Rule applied: {rule_applied}")
            
            # You could also combine them into a results dictionary
            results = {
                "error": False,
                "rf_probability": rf_prob,
                "bert_probability": bert_prob,
                "cnn_probability": cnn_prob,
                "avarage_probability": avg_prob,
                "ensemble_decision": rule_applied,
                "is_phishing": is_phishing
            }
            
        except Exception as e:
            if verbose:
                print(f"❌ Error during analysis: {str(e)}")
            results = {
                "error": True,
                "message": f"Error during analysis: {str(e)}",
                "rf_probability": None,
                "bert_probability": None, 
                "cnn_probability": None,
                "avarage_probability": None,
                "ensemble_decision": None,
                "is_phishing": None
            }
        
        # Clean up the temporary directory
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                if verbose:
                    print(f"✅ Directory temporanea {temp_dir} eliminata")
        except Exception as e:
            if verbose:
                print(f"⚠️ Impossibile eliminare la directory temporanea: {e}")
                
        return results
    
    def predict_urls_df(self, config, urls_df, url_column='url', verbose=False):
        """
        Analyze multiple URLs from a pandas DataFrame using batch processing
        
        Args:
            config: Configuration for download
            urls_df (pd.DataFrame): DataFrame containing URLs to analyze
            url_column (str): Name of the column containing URLs
            verbose (bool): Whether to print detailed information during processing
            
        Returns:
            pd.DataFrame: Original DataFrame with additional columns for prediction results
        """
        urls_df.columns = ['url']
        #if url_column not in urls_df.columns:
        #    raise ValueError(f"URL column '{url_column}' not found in the DataFrame")
        
        # Initialize result columns
        result_df = urls_df.copy()
        result_df['rf_probability'] = None
        result_df['bert_probability'] = None
        result_df['cnn_probability'] = None
        result_df['avarage_probability'] = None
        result_df['ensemble_decision'] = None
        result_df['is_phishing'] = None
        result_df['error'] = False
        result_df['error_message'] = None
        
        
        # Create necessary directories
        temp_dir = os.path.join(os.getcwd(), 'temp')
        html_dir = os.path.join(temp_dir, 'html')
        results_dir = os.path.join(temp_dir, 'results')
        screenshot_dir = os.path.join(temp_dir, 'screenshot')
        
        # Create directories if they don't exist
        for directory in [temp_dir, html_dir, results_dir, screenshot_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)
                
        try:
            # Extract URLs
            urls = result_df[url_column].tolist()
            total_urls = len(urls)
            
            if verbose:
                print(f"Processing {total_urls} URLs in batch mode")
                
            # 1. Download pages in batch
            html_files = {}
            urls_to_capture = {}
            for idx, url in enumerate(urls):
                try:
                    domain = urlparse(url).netloc
                    file_name = f"{idx}_{domain}.html"
                    file_path = os.path.join(html_dir, file_name)
                    
                    downloaded_url, downloaded_path = download_temp_page(url, config, file_path, verbose=False)
                    if downloaded_path:
                        html_files[idx] = downloaded_path
                        urls_to_capture[idx] = downloaded_url
                    else:
                        result_df.at[idx, 'error'] = True
                        result_df.at[idx, 'error_message'] = f"Failed to download page from {url}"
                except Exception as e:
                    result_df.at[idx, 'error'] = True
                    result_df.at[idx, 'error_message'] = f"Error downloading page: {str(e)}"
                    
            if verbose:
                print(f"Downloaded {len(html_files)} pages successfully")
                
            # 2. Capture screenshots in parallel
            screenshot_csv_path = os.path.join(results_dir, 'screenshot_results.csv')
            #urls_to_capture = [urls[idx] for idx in html_files.keys()]
            
            batch_capture_screenshots_parallel(
                urls_to_capture, 
                screenshot_dir, 
                results_dir=results_dir,
                verbose=verbose
            )
            
            # Load screenshot results
            screenshot_df = pd.DataFrame()
            if os.path.exists(screenshot_csv_path):
                screenshot_df = pd.read_csv(screenshot_csv_path)
                if verbose:
                    print(f"Captured {len(screenshot_df)} screenshots successfully")      
            # 3. Extract features for Random Forest
            rf_df = create_test_csv(os.path.join(results_dir, 'temp.csv'), 
                                   os.path.join(results_dir, 'parsed_temp.csv'),
                                   verbose=False)
            
            # 4. Extract features for BERT
            test_text = os.path.join(results_dir, "html_test_text.csv")
            test_numeric = os.path.join(results_dir, "html_test_numeric.csv")
            
            _, test_df_text = process_directory(
                html_dir,
                test_numeric,
                test_text)
                
            bert_text = clean_text_features(test_df_text)
            bert_features = bert_text["text_combined"].tolist()
            
            # 5. Extract features for CNN
            url_to_image_map = {}
            # Process images for CNN predictions
            if not screenshot_df.empty:
                for _, row in screenshot_df.iterrows():
                    url_to_image_map[row['ogidx']] = row['screenshot_path']
            # Preprocess images
            def preprocess_image(img_path, target_size=(224, 224)):
                try:
                    img = tf.keras.preprocessing.image.load_img(img_path, target_size=target_size)
                    img_array = tf.keras.preprocessing.image.img_to_array(img)
                    img_array = np.expand_dims(img_array, axis=0)  # Create batch axis
                    img_array = img_array / 255.0  # Rescale
                    return img_array
                except Exception as e:
                    if verbose:
                        print(f"⚠️ Error processing image {img_path}: {e}")
                    return None
            
            # 6. Make predictions
            # RF predictions
            rf_predictions = self.rf_model.predict_proba(rf_df.drop('is_phishing', axis=1))[:, 1]
            
            # BERT predictions
            bert_predictions = self.bert_model.predict(bert_features)['phishing_probability']
            
            # 7. Process results and apply ensemble logic
            # Load ensemble configuration
            try:
                with open(self.ensemble_config_path, 'r') as f:
                    loaded_ensemble_config = json.load(f)
                
                # Get ensemble parameters
                avg_threshold = loaded_ensemble_config['ensemble_parameters']['avg_prediction_threshold']
                
                # Parameters for Rule 1 (RF direct phishing)
                rule1_rf_thresh = loaded_ensemble_config['ensemble_parameters']['rules']['rf_direct_phishing']['rf_threshold']
                
                # Parameters for Rule 2 (CNN & RF phishing)
                rule2_cnn_thresh = loaded_ensemble_config['ensemble_parameters']['rules']['cnn_rf_phishing']['cnn_threshold']
                rule2_rf_thresh = loaded_ensemble_config['ensemble_parameters']['rules']['cnn_rf_phishing']['rf_threshold']
                
                # Parameters for Rule 3 (BERT & RF phishing)
                rule3_bert_thresh = loaded_ensemble_config['ensemble_parameters']['rules']['bert_rf_phishing']['bert_threshold'] 
                rule3_rf_thresh = loaded_ensemble_config['ensemble_parameters']['rules']['bert_rf_phishing']['rf_threshold']
            except Exception as e:
                if verbose:
                    print(f"⚠️ Error loading ensemble configuration: {e}. Using default thresholds.")
                # Default ensemble parameters if loading fails
                avg_threshold = 0.6
                rule1_rf_thresh = 0.8
                rule2_cnn_thresh = 0.99
                rule2_rf_thresh = 0.5
                rule3_bert_thresh = 0.99
                rule3_rf_thresh = 0.5
            
            # Process each URL's results
            processed_count = 0
            phishing_count = 0
            
            for idx, row in rf_df.iterrows():
                avg_prob = None
                original_idx = idx  # Map back to original DataFrame index
                
                if original_idx < len(result_df):
                    # Get model probabilities
                    rf_prob = float(rf_predictions[idx])
                    bert_prob = float(bert_predictions[idx])
                    
                    # Get CNN probability if available
                    cnn_prob = None
                    if original_idx in url_to_image_map:
                        img_path = url_to_image_map[original_idx]
                        img_array = preprocess_image(img_path)
                        if img_array is not None:
                            cnn_prob = float(self.cnn_model.predict(img_array, verbose=0)[0][0])
                    
                    # Apply ensemble rules
                    is_phishing = False
                    rule_applied = "No rule applied"
                    
                    valid_models_count = 3 if cnn_prob is not None else 2
                    
                    # Rule 1: If RF probability exceeds its threshold, classify as phishing
                    if rf_prob >= rule1_rf_thresh:
                        is_phishing = True
                        rule_applied = "Rule 1: RF direct phishing"
                    
                    # Rule 2: If CNN and RF both exceed their thresholds, classify as phishing
                    elif cnn_prob is not None and cnn_prob >= rule2_cnn_thresh and rf_prob >= rule2_rf_thresh:
                        is_phishing = True
                        rule_applied = "Rule 2: CNN & RF phishing"
                    
                    # Rule 3: If BERT and RF both exceed their thresholds, classify as phishing
                    elif bert_prob >= rule3_bert_thresh and rf_prob >= rule3_rf_thresh:
                        is_phishing = True
                        rule_applied = "Rule 3: BERT & RF phishing"
                    
                    # Average probability calculation (exclude CNN if not available)
                    else:
                        # Calculate average of available model probabilities
                        avg_prob = 0
                        if valid_models_count == 3:
                            avg_prob = (rf_prob + bert_prob + cnn_prob) / 3
                        else:
                            avg_prob = (rf_prob + bert_prob) / 2
                            
                        # Apply average threshold
                        if avg_prob >= avg_threshold:
                            is_phishing = True
                            rule_applied = f"Average probability ({avg_prob:.4f}) exceeds threshold ({avg_threshold})"
                        else:
                            rule_applied = f"Average probability ({avg_prob:.4f}) below threshold ({avg_threshold})"
                    
                    # Update result dataframe
                    result_df.at[original_idx, 'rf_probability'] = rf_prob
                    result_df.at[original_idx, 'bert_probability'] = bert_prob
                    result_df.at[original_idx, 'cnn_probability'] = cnn_prob
                    result_df.at[original_idx, 'avarage_probability'] = avg_prob
                    result_df.at[original_idx, 'ensemble_decision'] = rule_applied
                    result_df.at[original_idx, 'is_phishing'] = is_phishing
                    
                    processed_count += 1
                    if is_phishing:
                        phishing_count += 1
            
            if verbose:
                print(f"Processed {processed_count} URLs. Found {phishing_count} phishing URLs.")
                
        except Exception as e:
            if verbose:
                print(f"Error during batch processing: {str(e)}")
        finally:
            # Clean up temporary directory
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                    if verbose:
                        print(f"✅ Temporary directory {temp_dir} removed")
            except Exception as e:
                if verbose:
                    print(f"⚠️ Unable to remove temporary directory: {e}")
        
        return result_df