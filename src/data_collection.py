import os
import pandas as pd
import requests
from io import StringIO
import random
import json
import re
from urllib.parse import urlparse
import time
from fake_useragent import UserAgent
import hashlib

def get_random_headers():
    """Generate random headers for requests."""
    ua = UserAgent()
    return {
        'User-Agent': ua.random,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    }

def get_tranco_domains(config):
    df = pd.read_csv(config["data_collection"]["tranco_file"], header=None, usecols=[1], names=["domain"])
    print(f"Caricati {len(df)-1} domini da Tranco")
    return df["domain"].tolist()

def check_site_availability(url):
    try:
        response = requests.get(url, timeout=5, headers=get_random_headers())
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def get_commoncrawl_urls(domain, config, timeout=10):
    """
    Recupera 3 URL unici da CommonCrawl per un dominio specifico.
    """
    urls = []
    seen_urls = set()  # Per evitare duplicati
    max_urls = 3  # Numero di URL che vogliamo per dominio
    
    try:
        response = requests.get(
            config["data_collection"]["commoncrawl_api"].format(domain), 
            timeout=timeout,
            headers=get_random_headers()
        )
        if response.status_code != 200:
            print(f"🚨 ERRORE: CommonCrawl ha restituito {response.status_code} per {domain}")
            return []

        # Verifichiamo che il dominio sia raggiungibile
        first_url = f"http://{domain}"
        if not check_site_availability(first_url):
            print(f"⚠️ Il dominio {domain} non risponde, saltato")
            return []

        # Raccogliamo 3 URL unici
        for line in response.text.splitlines():
            if len(urls) >= max_urls:
                break
                
            try:
                entry = json.loads(line)
                url = entry.get("url")
                if url:
                    # Normalizza l'URL rimuovendo protocollo, www e slash finale
                    normalized_url = re.sub(r'^https?:\/\/(www\.)?', '', url).rstrip('/')
                    if normalized_url not in seen_urls:
                        seen_urls.add(normalized_url)
                        if check_site_availability(url):
                            urls.append(url)
                            print(f"✅ Trovato e accessibile: {url}")
            except json.JSONDecodeError:
                continue

        if not urls:
            print(f"⚠️ Nessun URL valido trovato per {domain}")

    except requests.Timeout:
        print(f"⚠️ Timeout durante la richiesta per {domain}")
        return []
    except Exception as e:
        print(f"⚠️ Errore nel recupero URL per {domain}: {str(e)}")
        return []

    print(f"🔎 Trovati {len(urls)}/{max_urls} URL validi per {domain}")
    return urls


def sanitize_filename(url, config):
    parsed_url = urlparse(url)
    # Usa solo il dominio
    base_name = parsed_url.netloc
    
    # Aggiungi un hash corto dell'URL completo per garantire unicità
    url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
    base_name += f"_{url_hash}"

    # Rimuovi caratteri non ASCII
    base_name = ''.join(c for c in base_name if ord(c) < 128)
    
    # Rimuovi caratteri non consentiti
    base_name = re.sub(r'[<>:"/\\|?*]', '_', base_name)
    
    # Rimuovi underscore multipli
    base_name = re.sub(r'_+', '_', base_name)
    
    # Tronca il nome se troppo lungo, ma preserva l'estensione
    max_length = config["data_collection"]["legit_sites"]["max_filename_length"]
    if len(base_name) > max_length:
        base_name = base_name[:max_length-5]  # -5 per .html
    
    return base_name + ".html"

def save_html(url, domain, config):
    try:
        response = requests.get(url, timeout=5, headers=get_random_headers())
        if response.status_code == 200:
            safe_filename = sanitize_filename(url, config)
            filepath = os.path.join(config["paths"]["raw_legit"], safe_filename)
            
            if not os.path.exists(filepath):
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(response.text)
                
                csv_path = os.path.join(config["paths"]["results"], "legit_sites.csv")
                df = pd.DataFrame([[domain, url, filepath]], columns=["domain", "url", "html_file"])
                df.to_csv(csv_path, 
                         index=False, 
                         mode='a', 
                         header=not os.path.exists(csv_path))
                
                return filepath
    except requests.RequestException as e:
        print(f"Errore nel download di {url}: {e}")
    return None

def download_phishing_data(config):
    """
    Scarica i dati di phishing dal file CSV pulito.
    
    Args:
        config: Configurazione con i percorsi
        
    Returns:
        DataFrame con i domini, gli URL e i percorsi dei file HTML scaricati
    """
    # Percorsi
    raw_phishing_path = config['paths']['raw_phishing']
    os.makedirs(raw_phishing_path, exist_ok=True)
    
    # File CSV di output
    output_csv = os.path.join('data', 'results', 'phish_sites.csv')
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    
    # Carica il file CSV con i siti di phishing
    input_file = config["data_collection"]["phish_file"]
    if not os.path.exists(input_file):
        print(f"File {input_file} non trovato!")
        return pd.DataFrame()
    
    # Carica il dataframe con i siti di phishing
    try:
        phish_df = pd.read_csv(input_file)
        print(f"Caricati {len(phish_df)} siti di phishing dal file")
    except Exception as e:
        print(f"Errore nel caricamento del file phishing: {e}")
        return pd.DataFrame()
    
    # Controlla se esiste già il file CSV di output e caricalo
    existing_urls = set()
    if os.path.exists(output_csv):
        existing_df = pd.read_csv(output_csv)
        existing_urls = set(existing_df['url'])

    # Lista per i nuovi siti scaricati
    results = []
    successful_downloads = 0
    
    sample_size = min(10000, len(phish_df))
    sampled_sites = phish_df.sample(n=sample_size)
    
    for index, row in sampled_sites.iterrows():
        url = row['Url']
        
        # Skip se l'URL è già stato scaricato
        if url in existing_urls:
            print(f"⏩ URL già processato: {url}")
            continue
            
        domain = urlparse(url).netloc
        print(f"\nProcessando {url} (dominio: {domain})")
        
        # Verifica disponibilità del sito
        try:
            is_available = check_site_availability(url)
            if not is_available:
                print(f"⚠️ URL non raggiungibile: {url}")
                
                # Rimuovi immediatamente il sito non raggiungibile dal dataframe originale
                phish_df = phish_df[phish_df['Url'] != url]
                # Salva il dataframe aggiornato
                phish_df.to_csv(input_file, index=False)
                print(f"✅ URL rimosso dal file sorgente: {url}")
                
                continue
                
            # Scarica l'HTML del sito
            response = requests.get(url, timeout=5, headers=get_random_headers())
            if response.status_code == 200:
                safe_filename = sanitize_filename(url, config)
                filepath = os.path.join(raw_phishing_path, safe_filename)
                
                if not os.path.exists(filepath):
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(response.text)
                    
                    df = pd.DataFrame([[domain, url, filepath]], 
                                   columns=["domain", "url", "html_file"])
                    df.to_csv(output_csv, 
                            index=False, 
                            mode='a', 
                            header=not os.path.exists(output_csv))
                    
                    results.append({
                        "domain": domain,
                        "url": url,
                        "html_file": filepath,
                    })
                    
                    successful_downloads += 1
                    print(f"✅ Salvato {filepath}")
                    print(f"🔵 Siti phishing scaricati: {successful_downloads}")
                    
                    time.sleep(config["data_collection"]["phishing_sites"]["request_delay"])
            else:
                print(f"⚠️ URL non valido (status code {response.status_code}): {url}")
                # Rimuovi anche per status code non valido
                phish_df = phish_df[phish_df['Url'] != url]
                phish_df.to_csv(input_file, index=False)
                print(f"✅ URL rimosso dal file sorgente: {url}")
                
        except Exception as e:
            print(f"🚨 Errore nel download di {url}: {e}")
            
            # Rimuovi anche in caso di errore generico
            phish_df = phish_df[phish_df['Url'] != url]
            phish_df.to_csv(input_file, index=False)
            print(f"✅ URL rimosso dal file sorgente a causa di errore: {url}")
            
            continue

    return pd.DataFrame(results) if results else pd.DataFrame()

def download_legit_data(config):
    """
    Scarica i dati dei siti legittimi usando CommonCrawl.
    """    
    domains = get_tranco_domains(config)
    sampled_domains = random.sample(domains, 1000)
    
    results = []
    successful_downloads = 0
    
    for domain in sampled_domains:
        try:
            print(f"\n🌍 Recupero URL per il dominio: {domain}")
            urls = get_commoncrawl_urls(domain, config, timeout=10)
            
            if not urls:
                print(f"⚠️ Nessun URL trovato per {domain}, passo al successivo")
                continue
                
            success_for_domain = False
            valid_urls = 0
            
            for url in urls:
                try:
                    print(f"⏳ Scaricamento di {url}")
                    filepath = save_html(url, domain, config)
                    if filepath:
                        print(f"✅ Salvato {filepath}")
                        results.append({
                            "domain": domain,
                            "url": url,
                            "html_file": filepath
                        })
                        success_for_domain = True
                        valid_urls += 1
                        
                        if valid_urls >= config["data_collection"]["legit_sites"]["limit_per_domain"]:
                            break
                            
                except Exception as e:
                    print(f"⚠️ Errore nel salvare {url}: {str(e)}")
                    continue
                    
                time.sleep(config["data_collection"]["legit_sites"]["request_delay"])
            
            if success_for_domain:
                successful_downloads += 1
                print(f"\n🔵 Domini scaricati correttamente: {successful_downloads} 🔵")
            else:
                print(f"⚠️ Nessun URL valido per {domain}")
                
        except Exception as e:
            print(f"🚨 Errore durante l'elaborazione di {domain}: {str(e)}")
            continue
            
        # Aggiungi un delay extra ogni 50 domini per evitare rate limiting
        if successful_downloads % 50 == 0:
            print("\n⏳ Pausa di 30 secondi per evitare rate limiting...")
            time.sleep(30)
    
    return pd.DataFrame(results) if results else pd.DataFrame()

def download_test_page(url, config, is_phishing):
    """
    Downloads HTML from a URL and saves it for testing.
    Returns the saved file path or None if download fails.
    """
    try:
        response = requests.get(url, timeout=5, headers=get_random_headers())
        if response.status_code == 200:
            safe_filename = sanitize_filename(url, config)
            filepath = os.path.join(config["paths"]["raw_test"], safe_filename)            
            if not os.path.exists(filepath):
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(response.text)                
                csv_path = os.path.join(config["paths"]["results"], "test.csv")
                df = pd.DataFrame([[url, filepath, is_phishing]], 
                               columns=["url", "html_file", "is_phishing"])
                df.to_csv(csv_path, 
                        index=False, 
                        mode='a', 
                        header=not os.path.exists(csv_path))
                print(f"✅ Saved {filepath}")
                return filepath    
    except Exception as e:
        print(f"🚨 Error downloading {url}: {e}")
    return None

def download_temp_page(url, config, is_phishing=True, verbose=False):
    """
    Tenta il download di una pagina HTML da un singolo URL.
    Prova prima con HTTPS, poi con HTTP se fallisce.
    Salva il file HTML e logga il risultato in 'temp/'.
    
    Args:
        url: URL da scaricare
        config: Configurazione con i percorsi
        is_phishing: Indicatore se l'URL è di phishing
        verbose: Se True, stampa messaggi informativi
    """
    def try_download(target_url):
        try:
            response = requests.get(target_url, timeout=5, headers=get_random_headers())
            if response.status_code == 200:
                # Prepara i percorsi
                os.makedirs("temp/html", exist_ok=True)
                os.makedirs("temp/results", exist_ok=True)

                safe_filename = sanitize_filename(target_url, config)
                filepath = os.path.join("temp/html", safe_filename)

                if not os.path.exists(filepath):
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(response.text)

                    # Salva il log nel CSV
                    csv_path = os.path.join("temp/results", "temp.csv")
                    df = pd.DataFrame([[target_url, filepath, is_phishing]],
                                      columns=["url", "html_file", "is_phishing"])
                    df.to_csv(csv_path,
                              index=False,
                              mode='a',
                              header=not os.path.exists(csv_path))

                    if verbose:
                        print(f"✅ Download riuscito e salvato in: {filepath}")
                else:
                    if verbose:
                        print(f"ℹ️ File già esistente: {filepath}")
                return target_url, filepath
        except Exception as e:
            if verbose:
                print(f"⚠️ Errore durante il tentativo con {target_url}: {e}")
        return target_url, ""

    # Aggiusta il protocollo se manca
    if not url.startswith(("http://", "https://")):
        original_url = url
        https_url = "https://" + url
        http_url = "http://" + url
        if verbose:
            print(f"\n🔍 Inizio il download per: {original_url}")
            print(f"Tentativo con HTTPS: {https_url}")
        result = try_download(https_url)
        if result:
            return result
        if verbose:
            print(f"Tentativo con HTTP: {http_url}")
        return try_download(http_url)
    else:
        if verbose:
            print(f"\n🔍 Inizio il download per: {url}")
        return try_download(url)
