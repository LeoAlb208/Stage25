import ast
import pandas as pd

def clean_text_features(df):
    """
    Pulisce i dati testuali nel DataFrame e li formatta in una stringa strutturata.
    
    Args:
        df (pd.DataFrame): DataFrame con i dati testuali
    
    Returns:
        pd.DataFrame: DataFrame pulito con testo formattato
    """
    # Crea una copia per non modificare l'originale
    df = df.copy()
    
    # Rimuovi .html dai filename
    df['filename'] = df['filename'].str.replace('.html', '')
    
    # Converti la stringa della lista in lista effettiva e unisci con virgole
#    df['external_domains_list'] = df['external_domains_list'].apply(lambda x: 
#        ', '.join(ast.literal_eval(x)) if pd.notnull(x) and x != '[]' else 'NULL')
    import ast

    def process_external_domains(x):
        if isinstance(x, str):
            try:
                parsed = ast.literal_eval(x)
                if isinstance(parsed, list) and len(parsed) > 0:
                    return ', '.join(parsed)
            except (ValueError, SyntaxError):
                pass
        return 'NULL'

    df['external_domains_list'] = df['external_domains_list'].apply(process_external_domains)
    # Gestione valori mancanti
    df['title'] = df['title'].fillna('NULL')
    df['description'] = df['description'].fillna('NULL')
    
    # Pulisci i singoli campi
    for col in ['filename', 'title', 'description', 'external_domains_list']:
        df[col] = df[col].astype(str)
        df[col] = df[col].apply(lambda x: x.strip())
        df[col] = df[col].apply(lambda x: x.replace('\n', ' '))
        df[col] = df[col].apply(lambda x: x.replace('\r', ' '))
        df[col] = df[col].apply(lambda x: ' '.join(x.split()))  # Rimuove spazi multipli
        df[col] = df[col].apply(lambda x: 'NULL' if x == '' or x.isspace() else x)
    
    # Formatta il testo combinato nella struttura richiesta
    df['text_combined'] = df.apply(lambda row: 
        f"[FILENAME] {row['filename']} " + 
        f"[TITLE] {row['title']} " + 
        f"[DESCRIPTION] {row['description']} " + 
        f"[EXTERNAL_DOMAINS_LIST] {row['external_domains_list']}", 
        axis=1
    )
    
    return df