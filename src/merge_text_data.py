import pandas as pd

def merge_text_features(legit_csv_path, phishing_csv_path, random_state=42):
    """
    Unisce i dati testuali dai file CSV dei siti legittimi e di phishing.
    
    Args:
        legit_csv_path (str): Percorso del CSV con i dati testuali dei siti legittimi
        phishing_csv_path (str): Percorso del CSV con i dati testuali dei siti di phishing
        random_state (int): Seme per la riproducibilità dello shuffle
    
    Returns:
        pd.DataFrame: DataFrame contenente tutti i dati testuali con colonna is_phishing
    """
    # Carica i CSV
    legit_df = pd.read_csv(legit_csv_path)
    phish_df = pd.read_csv(phishing_csv_path)
    
    # Aggiungi colonna is_phishing
    legit_df['is_phishing'] = 0
    phish_df['is_phishing'] = 1
    
    # Unisci i DataFrame
    merged_df = pd.concat([legit_df, phish_df], ignore_index=True)
    
    # Shuffle del DataFrame
    merged_df = merged_df.sample(frac=1, random_state=random_state).reset_index(drop=True)
    
    return merged_df