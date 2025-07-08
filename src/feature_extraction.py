import re
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import pandas as pd
import math
import numpy as np
import tldextract
import os
import yaml

# Load config
def load_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'configs', 'config.yaml')
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

CONFIG = load_config()

# Constants
SHORTENERS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), CONFIG['paths']['shorteners'])

def load_shorteners(filepath):
    """Legge il file e estrae la lista di shorteners."""
    shorteners = set()
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            match = re.search(r'"([^"]+)"', line)
            if match:
                shorteners.add(match.group(1).lower())  # Normalizza in minuscolo
    return shorteners

# Load shorteners
SHORTENERS = load_shorteners(SHORTENERS_FILE)

# Suspicious TLDs
SUSPICIOUS_TLDS = {
    # TLD gratuiti o economici spesso abusati
    'gq', 'tk', 'ml', 'cf', 'ga', 'biz', 'info', 'top', 'xyz', 'club',  
    'online', 'site', 'fun', 'win', 'loan', 'men', 'bid', 'date', 'wang',  

    # TLD recentemente popolari tra i cybercriminali
    'zip', 'mov', 'cam', 'cyou', 'icu', 'rest', 'quest', 'bond',  
    'beauty', 'makeup', 'hair', 'skin', 'monster', 'boo', 'work',  

    # TLD associati a schemi di truffa
    'review', 'trade', 'stream', 'download', 'racing', 'party',  
    'accountant', 'science', 'faith', 'cricket', 'space',  

    # TLD con alto tasso di abuso
    'country', 'xin', 'kim', 'link', 'press', 'cloud', 'live',  
    'host', 'homes', 'world', 'press', 'market', 'casino',  

    # TLD che spesso imitano servizi legittimi
    'support', 'help', 'bank', 'services', 'solutions', 'corp',  
    'email', 'media', 'pro', 'group', 'company',  

    # Nuove estensioni potenzialmente rischiose
    'phd', 'mba', 'guru', 'degree', 'repair', 'exposed', 'gratis',  
    'wtf', 'sucks', 'black', 'red', 'blue', 'green', 'pink',
}

# Phishing hints
PHISH_HINTS = {
    'secure', 'account', 'verify', 'login', 'update', 'free', 'bonus', 'confirm',  
    'bank', 'payment', 'credit', 'debit', 'transaction', 'security',  
    'alert', 'suspend', 'warning', 'unlock', 'activation', 'reset', 'support',  
    'service', 'customer', 'important', 'urgent', 'billing', 'insurance',  
    'authentication', 'identity', 'access', 'limited', 'message',  
    'notification', 'restricted', 'recovery', 'password', 'renewal',  
    'official', 'refund', 'submit', 'updateinfo', 'restore', 'checkout',  
    'prize', 'gift', 'winner', 'survey', 'lucky', 'claim', 'earn',  
    'download', 'invoice', 'statement', 'tax', 'government', 'crypto',  
    'wallet', 'investment', 'trading', 'lottery', 'bills', 'escrow',  
    'promotion', 'subscription', 'activation', 'signin', 'webscr'
}

# Brand names
BRAND_NAMES = {
    # Tecnologia e Software
    'microsoft', 'windows', 'office', 'azure', 'github', 'adobe', 'photoshop',  
    'autodesk', 'oracle', 'sap', 'ibm', 'salesforce', 'zoom', 'dropbox',  
    'slack', 'notion', 'trello', 'figma', 'canva', 'evernote',  

    # Social Media e Comunicazione
    'facebook', 'meta', 'instagram', 'whatsapp', 'messenger', 'twitter',  
    'x', 'linkedin', 'snapchat', 'tiktok', 'telegram', 'discord',  
    'reddit', 'pinterest', 'wechat', 'viber', 'skype', 'tumblr',  

    # Streaming e Intrattenimento
    'netflix', 'hulu', 'disney', 'disneyplus', 'primevideo', 'hbo',  
    'spotify', 'deezer', 'tidal', 'soundcloud', 'youtube', 'twitch',  

    # Cloud e Email
    'gmail', 'outlook', 'hotmail', 'yahoo', 'icloud', 'protonmail',  
    'zoho', 'fastmail', 'mailchimp', 'sendgrid',  

    # E-commerce e Retail
    'amazon', 'ebay', 'aliexpress', 'alibaba', 'shopify', 'etsy',  
    'rakuten', 'flipkart', 'mercadolibre', 'zalando', 'ikea',  
    'target', 'walmart', 'costco', 'bestbuy', 'homedepot', 'wayfair',  

    # Finanza e Pagamenti
    'paypal', 'venmo', 'zelle', 'stripe', 'square', 'skrill', 'paysafecard',  
    'mastercard', 'visa', 'americanexpress', 'discover', 'revolut',  
    'cashapp', 'wise', 'westernunion', 'moneygram',  

    # Criptovalute e Trading
    'binance', 'coinbase', 'kraken', 'blockchain', 'trustwallet',  
    'metamask', 'bitfinex', 'bittrex', 'gemini', 'etoro', 'robinhood',  
    'fidelity', 'vanguard', 'charlesSchwab', 'interactivebrokers',  

    # Banche e Assicurazioni
    'bankofamerica', 'chase', 'wellsfargo', 'citi', 'hsbc', 'barclays',  
    'natwest', 'lloyds', 'tdbank', 'scotiabank', 'bnp', 'societegenerale',  
    'unicredit', 'ing', 'santander', 'creditagricole', 'allianz', 'axa',  

    # Viaggi e Trasporti
    'uber', 'lyft', 'airbnb', 'booking', 'expedia', 'trivago',  
    'delta', 'ryanair', 'emirates', 'britishairways', 'lufthansa',  
    'qatarairways', 'americanairlines', 'alaskaair',  

    # Logistica e Spedizioni
    'dhl', 'fedex', 'ups', 'usps', 'tnt', 'dpd', 'gls',  

    # Gaming
    'steam', 'epicgames', 'playstation', 'xbox', 'nintendo', 'rockstargames',  
    'blizzard', 'riotgames', 'bethesda', 'ubisoft', 'ea', 'activision',  

    # Governi e Servizi Pubblici
    'gov', 'irs', 'revenue', 'uscis', 'nhs', 'europa', 'inps', 'agenziaentrate',  
    'poste', 'anpr', 'dvla', 'revenuequebec',
}

def split_words(text):
    """Divide il testo in parole usando caratteri non alfanumerici come separatori."""
    return [word for word in re.split(r'\W+', text) if word]

def compute_entropy(s):
    """Calcola l'entropia di Shannon di una stringa."""
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return - sum([p * math.log(p, 2) for p in prob]) if s else 0

def max_repeating_char(text):
    """Restituisce il numero massimo di ripetizioni consecutive di uno stesso carattere."""
    max_count = 0
    count = 0
    last_char = ''
    for char in text:
        if char == last_char:
            count += 1
        else:
            count = 1
            last_char = char
        if count > max_count:
            max_count = count
    return max_count

def extract_all_url_features(url):
    features = {}
    url_lower = url.lower()
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    path = parsed.path.lower()
    
    # f1: Lunghezza intera dell'URL
    features['f1_url_length'] = len(url)
    
    # f2: Lunghezza del nome host
    features['f2_hostname_length'] = len(hostname)
    
    # f3: Presenza di indirizzo IP nel hostname
    ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    features['f3_has_ip'] = 1 if ip_pattern.match(hostname) else 0
    
    # f4-f20: Conteggi di caratteri speciali nell'URL
    specials = {
        'f4_dot': '.',
        'f5_hyphen': '-',
        'f6_at': '@',
        'f7_question': '?',
        'f8_ampersand': '&',
        'f9_pipe': '|',
        'f10_equal': '=',
        'f11_underscore': '_',
        'f12_tilde': '~',
        'f13_percent': '%',
        'f14_slash': '/',
        'f15_asterisk': '*',
        'f16_colon': ':',
        'f17_comma': ',',
        'f18_semicolon': ';',
        'f19_dollar': '$'
    }
    for key, char in specials.items():
        features[key] = url.count(char)
    # f20: Conteggio di '%20' e spazi
    features['f20_space_or_%20'] = url.count('%20') + url.count(' ')
    
    # f21-f24: Conteggio di termini comuni
    features['f21_www'] = url_lower.count('www')
    features['f22_.com'] = url_lower.count('.com')
    features['f23_http'] = url_lower.count('http')
    features['f24_//'] = url_lower.count('//')
    
    # f25: Token HTTPS
    features['f25_https'] = 1 if parsed.scheme == 'https' else 0
    
    # f26: Rapporto di cifre nell'URL
    digits_url = sum(c.isdigit() for c in url)
    features['f26_ratio_digits_url'] = digits_url / len(url) if len(url) > 0 else 0
    
    # f27: Rapporto di cifre nel hostname
    digits_host = sum(c.isdigit() for c in hostname)
    features['f27_ratio_digits_hostname'] = digits_host / len(hostname) if len(hostname) > 0 else 0
    
    # f28: Punycode (check if hostname contains 'xn--')
    features['f28_punycode'] = 1 if 'xn--' in hostname else 0
    
    # f29: Presenza di porta
    features['f29_port'] = 1 if parsed.port is not None else 0
    
    # Estrazione del TLD: semplice ipotesi, l'ultima parte dopo l'ultimo '.'
    tld = hostname.split('.')[-1] if '.' in hostname else ''
    
    # f30: TLD appare nel path
    features['f30_tld_in_path'] = 1 if tld and tld in path else 0
    
    # f31: TLD appare nella parte di subdomain (parte del hostname escluso dominio registrato)
    ext = tldextract.extract(url)

    tld = ext.suffix
    subdomains = ext.subdomain.split('.') if ext.subdomain else []
    features['f31_tld_in_subdomain'] = 1 if any(tld in sub for sub in subdomains) and tld else 0
    
    # f32: Abnormal subdomains
    # Controlla se il subdominio segue il pattern 'w{1,2}[0-9]*' e non è esattamente "www", 
    # oppure se è "www" seguito da un numero.
    abnormal = 0
    for sub in subdomains:
        if (re.fullmatch(r'w{1,2}\d*', sub) and sub != 'www') or (sub.startswith('www') and sub[3:].isdigit()):
            abnormal = 1
            break
    features['f32_abnormal_subdomain'] = abnormal

    # f33: Numero di subdomini (se len(parts) > 2, altrimenti 0)
    parts = hostname.split('.')
    features['f33_num_subdomains'] = len(parts) - 2 if len(parts) > 2 else 0
    
    # f34: Prefix-Suffix (presenza di '-' nel dominio)
    features['f34_prefix_suffix'] = 1 if '-' in hostname else 0
    
    # f35: Random domains: si usa l'entropia della parte registrata (assumiamo ultime due parti)
    if len(parts) >= 2:
        registered_domain = '.'.join(parts[-2:])
    else:
        registered_domain = hostname
    entropy = compute_entropy(registered_domain)
    # Soglia scelta empiricamente, ad esempio > 4.0
    features['f35_random_domain'] = 1 if entropy > 4.0 else 0
    
    # f36: URL shortening service
    features['f36_shortening_service'] = 1 if hostname in SHORTENERS else 0
    
    # f37: Path extension (controlla se il path termina con '.txt', '.exe' o '.js')
    features['f37_path_extension'] = 1 if path.endswith(('.txt', '.exe', '.js')) else 0
    
    # f38 & f39: Redirezioni e redirezioni esterne
    # Proviamo a seguire le redirezioni (attenzione: questo può rallentare)
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        history = response.history
        features['f38_num_redirections'] = len(history)
        external_redir = 0
        original_domain = hostname
        for resp in history:
            redir_url = resp.headers.get('location', '')
            if redir_url:
                redir_parsed = urlparse(redir_url)
                redir_host = redir_parsed.netloc.lower()
                if redir_host and redir_host != original_domain:
                    external_redir += 1
        features['f39_num_external_redirections'] = external_redir
    except Exception:
        features['f38_num_redirections'] = 0
        features['f39_num_external_redirections'] = 0
    
    # f40-f50: Feature NLP (analisi di "parole" in URL, hostname e path)
    # Usiamo split_words per ottenere le parole separate
    words_url = split_words(url_lower)
    words_host = split_words(hostname)
    words_path = split_words(path)
    
    features['f40_num_words_url'] = len(words_url)
    features['f41_max_char_repeat_url'] = max_repeating_char(url_lower)
    
    def word_stats(words):
        if not words:
            return (0, 0, 0)  # (min, max, avg)
        lengths = [len(w) for w in words]
        return (min(lengths), max(lengths), sum(lengths)/len(lengths))
    
    # f42, f45, f48: URL (min, max, avg lunghezza parole)
    min_url, max_url, avg_url = word_stats(words_url)
    features['f42_shortest_word_url'] = min_url
    features['f45_longest_word_url'] = max_url
    features['f48_avg_word_length_url'] = avg_url
    
    # f43, f46, f49: Hostname
    min_host, max_host, avg_host = word_stats(words_host)
    features['f43_shortest_word_hostname'] = min_host
    features['f46_longest_word_hostname'] = max_host
    features['f49_avg_word_length_hostname'] = avg_host
    
    # f44, f47, f50: Path
    min_path, max_path, avg_path = word_stats(words_path)
    features['f44_shortest_word_path'] = min_path
    features['f47_longest_word_path'] = max_path
    features['f50_avg_word_length_path'] = avg_path
    
    # f51: Phish hints (conta occorrenze di parole sensibili nell'URL)
    count_phish = 0
    for hint in PHISH_HINTS:
        count_phish += url_lower.count(hint)
    features['f51_phish_hints'] = count_phish
    
    # f52-f54: Brand domains
    # Supponiamo di dividere il hostname in: subdomain (parte iniziale), dominio registrato (ultime 2 parti) e path.
    features['f52_brand_in_domain'] = 0
    features['f53_brand_in_subdomain'] = 0
    features['f54_brand_in_path'] = 0
    # f52: controllo nel dominio registrato
    for brand in BRAND_NAMES:
        if brand in registered_domain:
            features['f52_brand_in_domain'] = 1
            break
    # f53: controllo nei subdomini
    for sub in subdomains:
        for brand in BRAND_NAMES:
            if brand in sub:
                features['f53_brand_in_subdomain'] = 1
                break
        if features['f53_brand_in_subdomain'] == 1:
            break
    # f54: controllo nel path
    for brand in BRAND_NAMES:
        if brand in path:
            features['f54_brand_in_path'] = 1
            break
    
    # f55: Suspicious TLD
    features['f55_suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0
    
    
    return features

def create_features_dataframe(input_csv_path):
    """
    Create a DataFrame with extracted features from URLs in the input CSV file
    
    Args:
        input_csv_path (str): Path to the input CSV file containing URLs
        
    Returns:
        pandas.DataFrame: DataFrame with extracted features and phishing labels
    """
    # Load the complete dataset
    df = pd.read_csv(input_csv_path)
    
    # Extract features for each URL in the dataset
    features_list = []
    for url in df['url']:
        try:
            features = extract_all_url_features(url)
            features_list.append(features)
        except:
            # In case of error, insert a dictionary with null values
            features_list.append({k: 0 for k in extract_all_url_features(df['url'].iloc[0]).keys()})
    
    # Convert list of dictionaries to DataFrame
    features_df = pd.DataFrame(features_list)
    result_df = pd.concat([features_df, df['is_phishing']], axis=1)
    
    return result_df

def save_features(df, output_csv_path):
    """
    Save the features DataFrame to a CSV file
    
    Args:
        df (pandas.DataFrame): DataFrame containing the features
        output_csv_path (str): Path where to save the CSV file
    """
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
    
    # Save the DataFrame to CSV
    df.to_csv(output_csv_path, index=False)