import os
import pandas as pd
from src.feature_extraction import extract_all_url_features
from src.parsing import parse_html

def merge_features(url: str, html_path: str, is_phishing: bool = False) -> dict:
    """
    Unisce le features estratte dall'URL e dal file HTML in un unico dizionario.
    
    Args:
        url (str): L'URL da analizzare
        html_path (str): Il percorso al file HTML
        is_phishing (bool): Flag che indica se il campione è phishing
    
    Returns:
        dict: Dizionario contenente tutte le features unite
    """
    # Estrae le features dall'URL
    url_features = extract_all_url_features(url)
    
    # Estrae le features dal file HTML (senza passare is_phishing)
    html_features = parse_html(html_path)
    
    # Aggiunge is_phishing al dizionario delle features HTML
    html_features['is_phishing'] = is_phishing
    
    # Unisce i due dizionari
    merged_features = {**url_features, **html_features}
    
    return merged_features

def create_test_csv(csv_path, output_path, verbose=False):
    """
    Crea un file CSV finale con tutte le features estratte dai siti.
    
    Args:
        csv_path (str): Percorso al file CSV contenente i dati dei siti
    """
    # Verifica esistenza del file
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"File {csv_path} non trovato")
    
    # Legge il CSV di input
    sites_df = pd.read_csv(csv_path)
    
    # Crea il path per il file di output
    output_dir = os.path.join(os.path.dirname(os.path.dirname(csv_path)), 'trainingdata')
    os.makedirs(output_dir, exist_ok=True)
    
    # Processa il primo record per ottenere i nomi delle colonne
    first_features = merge_features(
        sites_df.iloc[0]['url'],
        sites_df.iloc[0]['html_file'],
        sites_df.iloc[0]['is_phishing']
    )
    
    # Crea il file CSV con le intestazioni
    pd.DataFrame([first_features]).to_csv(output_path, index=False, mode='w')
    
    # Processa i record rimanenti
    for idx in range(1, len(sites_df)):  # Parte da 1 per evitare di processare nuovamente il primo record
        try:
            record = sites_df.iloc[idx]
            features = merge_features(
                record['url'],
                record['html_file'],
                record['is_phishing']
            )
            # Aggiunge il record al CSV
            pd.DataFrame([features]).to_csv(output_path, index=False, mode='a', header=False)
            
            # Stampa il progresso ogni 10 record
            if idx % 10 == 0:
                print(f"Processati {idx} record su {len(sites_df)}")
                
        except Exception as e:
            print(f"Errore nel processare il record {idx}: {e}")
            continue
    if verbose:
        print(f"Elaborazione completata. Risultati salvati in {output_path}")
    return pd.read_csv(output_path)

def create_final_csv(csv_path):
    """
    Crea un file CSV finale con tutte le features estratte dai siti.
    
    Args:
        csv_path (str): Percorso al file CSV contenente i dati dei siti
    """
    # Verifica esistenza del file
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"File {csv_path} non trovato")
    
    # Legge il CSV di input
    sites_df = pd.read_csv(csv_path)
    
    # Crea il path per il file di output
    output_dir = os.path.join(os.path.dirname(os.path.dirname(csv_path)), 'trainingdata')
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, 'merged_features.csv')
    
    # Processa il primo record per ottenere i nomi delle colonne
    first_features = merge_features(
        sites_df.iloc[0]['url'],
        sites_df.iloc[0]['html_file'],
        sites_df.iloc[0]['is_phishing']
    )
    
    # Crea il file CSV con le intestazioni
    pd.DataFrame([first_features]).to_csv(output_path, index=False, mode='w')
    
    # Processa i record rimanenti
    for idx in range(1, len(sites_df)):  # Parte da 1 per evitare di processare nuovamente il primo record
        try:
            record = sites_df.iloc[idx]
            features = merge_features(
                record['url'],
                record['html_file'],
                record['is_phishing']
            )
            # Aggiunge il record al CSV
            pd.DataFrame([features]).to_csv(output_path, index=False, mode='a', header=False)
            
            # Stampa il progresso ogni 10 record
            if idx % 10 == 0:
                print(f"Processati {idx} record su {len(sites_df)}")
                
        except Exception as e:
            print(f"Errore nel processare il record {idx}: {e}")
            continue
    
    print(f"Elaborazione completata. Risultati salvati in {output_path}")
    return pd.read_csv(output_path)
