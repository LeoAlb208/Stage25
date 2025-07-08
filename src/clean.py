import os
import pandas as pd

def verify_data_integrity():
    """
    Verifies that all HTML files referenced in phish_sites.csv actually exist
    in the phishing directory and removes any records for missing files.
    """
    # Read files from the directory
    phishing_files = set(os.listdir('data/raw/phishing'))

    # Read the CSV file
    df = pd.read_csv('data/results/phish_sites.csv')
    
    # Remove 'data/raw/phishing/' prefix from html_file column
    df['html_file'] = df['html_file'].str.replace('data/raw/phishing/', '')
    
    # Keep only rows where html_file exists in the directory
    df_filtered = df[df['html_file'].isin(phishing_files)]
    
    # Restore the 'data/raw/phishing/' prefix
    df_filtered['html_file'] = 'data/raw/phishing/' + df_filtered['html_file']
    
    # Check if any records were removed
    removed_count = len(df) - len(df_filtered)
    
    if removed_count > 0:
        print(f"⚠️ Rimossi {removed_count} record senza file HTML corrispondente")
        df_filtered.to_csv('data/results/phish_sites.csv', index=False)
    else:
        print("✅ Dataset integro - Nessuna rimozione necessaria")