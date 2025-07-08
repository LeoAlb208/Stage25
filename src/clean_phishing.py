import pandas as pd
import numpy as np
from datetime import datetime
from urllib.parse import urlparse

def normalize_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")
    path = parsed.path.rstrip("/")
    return f"{domain}{path}"

def get_main_domain(url):
    parsed = urlparse(url)
    domain_parts = parsed.netloc.split('.')
    if len(domain_parts) > 2:
        return ".".join(domain_parts[-2:])
    return parsed.netloc

def clean_phishing_sites(input_file, output_file):
    """
    Pulisce e aggiorna il dataset dei siti di phishing.
    
    Args:
        input_file (str): Percorso del file CSV di input
        output_file (str): Percorso dove salvare il file CSV pulito
        
    Returns:
        tuple: (num_records, num_new) - Numero totale di record e numero di nuovi record
    """
    try:
        # Leggi il nuovo dataset
        df = pd.read_csv(input_file, skiprows=9, names=["Date", "Score", "Url", "IP"])
        
        # Pulizia base
        df = df.dropna()
        df['Date'] = pd.to_datetime(df['Date'], errors='coerce')
        
        # Filtra per score >= 5
        df = df[df["Score"] >= 5]
        
        # Normalizza URLs e domini
        df["Normalized_Url"] = df["Url"].apply(normalize_url)
        df = df.sort_values(by="Score", ascending=False).drop_duplicates(subset="Normalized_Url", keep="first")
        
        df["Main_Domain"] = df["Url"].apply(get_main_domain)
        df = df.sort_values(by="Score", ascending=False).drop_duplicates(subset="Main_Domain", keep="first")
        
        # Rimuovi colonne temporanee
        df = df.drop(columns=["Normalized_Url", "Main_Domain"])
        
        try:
            # Prova a leggere il dataset esistente
            old_df = pd.read_csv(output_file)
            old_df['Date'] = pd.to_datetime(old_df['Date'])
            
            # Filtra solo i record nuovi
            latest_date = old_df["Date"].max()
            new_records = df[df["Date"] > latest_date]
            
            # Unisci i dataset
            updated_df = pd.concat([old_df, new_records])
            updated_df = updated_df.sort_values('Date', ascending=False)
            
            # Applica nuovamente la pulizia al dataset unito
            updated_df["Normalized_Url"] = updated_df["Url"].apply(normalize_url)
            updated_df = updated_df.sort_values(by="Score", ascending=False).drop_duplicates(subset="Normalized_Url", keep="first")
            
            updated_df["Main_Domain"] = updated_df["Url"].apply(get_main_domain)
            updated_df = updated_df.sort_values(by="Score", ascending=False).drop_duplicates(subset="Main_Domain", keep="first")
            
            updated_df = updated_df.drop(columns=["Normalized_Url", "Main_Domain"])
            
            # Salva il dataset aggiornato
            updated_df.to_csv(output_file, index=False)
            
            num_new_records = len(updated_df) - len(old_df)
            return len(updated_df), num_new_records
            
        except FileNotFoundError:
            # Se il file non esiste, salva il nuovo dataset
            df.to_csv(output_file, index=False)
            return len(df), 0
            
    except Exception as e:
        print(f"Errore durante la pulizia del dataset: {e}")
        return 0, 0

def format_output(total_records, new_records, output_path):
    """
    Formatta il messaggio di output appropriato.
    
    Args:
        total_records (int): Numero totale di record
        new_records (int): Numero di nuovi record
        output_path (str): Percorso del file di output
        
    Returns:
        str: Messaggio formattato
    """
    if new_records == 0 and total_records > 0:
        return f"Dataset pulito salvato come {output_path}. Record finali: {total_records}"
    elif new_records > 0:
        return (f"Dataset aggiornato e sovrascritto come {output_path}. Record totali: {total_records}\n"
                f"Nuovi record aggiunti: {new_records}")
    else:
        return "Nessun record processato"