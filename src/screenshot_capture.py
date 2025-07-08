import os
import time
import pandas as pd
import hashlib
from urllib.parse import urlparse
from seleniumbase import Driver
import concurrent.futures
import logging

# Configurazione del logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(asctime)s - %(message)s')

def capture_screenshot(url, output_path, max_height=15000):
    """
    Capture a screenshot of a webpage using SeleniumBase.
    Scrolls to capture the entire page up to max_height pixels.
    """
    logging.info(f"Inizio cattura screenshot per {url}")

    driver = Driver(uc=True, headless=False, extension_dir="src\Idontcarecookies")
    
    try:
        driver.get(url)
        time.sleep(1.5)  # Attende il caricamento iniziale
        
        # Ottieni le dimensioni della pagina
        total_height = driver.execute_script("return document.body.scrollHeight")
        total_height = min(total_height, max_height)  # Limita l'altezza massima
        
        # Imposta la dimensione della finestra per catturare l'intera larghezza
        viewport_width = driver.execute_script("return document.documentElement.clientWidth")
        driver.set_window_size(viewport_width, total_height)
        
        # Scroll lentamente fino in fondo per caricare contenuti lazy-loaded
        current_height = 0
        while current_height < total_height:
            driver.execute_script(f"window.scrollTo(0, {current_height});")
            current_height += 500
            time.sleep(0.2)
        
        # Torna all'inizio e cattura lo screenshot
        driver.execute_script("window.scrollTo(0, 0);")
        time.sleep(0.3)  # Attende eventuali animazioni
        driver.save_screenshot(output_path)
        
        if os.path.exists(output_path):
            logging.info(f"✅ Screenshot salvato: {output_path}")
            return True
        return False
        
    except Exception as e:
        logging.error(f"❌ Errore su {url}")
        return False
    finally:
        driver.quit()  # Assicura che il driver venga chiuso

def generate_screenshot_filename(url):
    """Genera un nome file univoco basato sull'URL"""
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else "unknown"  # Prevenire nomi vuoti

    # Creare un hash dell'URL per evitare duplicati
    url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
    
    # Combinare dominio e hash
    filename = f"{domain}_{url_hash}.png"
    
    # Rimuovere caratteri non validi
    filename = "".join(c if c.isalnum() or c in "._-" else "_" for c in filename)
    
    return filename

def process_site(site_data, config, results_csv_path=None, lock=None):
    """Processa un singolo sito e ne cattura lo screenshot"""
    url = site_data['url']
    is_phishing = site_data.get('is_phishing', False)

    site_type = 'phishing' if is_phishing else 'legit'
    filename = generate_screenshot_filename(url)
    output_path = os.path.join(config['paths']['data'], 'raw', 'screenshots', site_type, filename)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    if os.path.exists(output_path):
        return {'url': url, 'screenshot_path': output_path, 'success': True}

    for attempt in range(3):
        try:
            success = capture_screenshot(url, output_path)
            if success:
                screenshot_path = output_path
                break
            time.sleep(attempt * 2)  # Exponential backoff
        except Exception as e:
            logging.error(f"Tentativo {attempt + 1} fallito per {url}")
    
    if screenshot_path:
        result_data = {
            'screenshot_path': screenshot_path,
            'domain': site_data['domain'],
            'hash_id': hashlib.md5(url.encode()).hexdigest()[:8],
            'is_phishing': 1 if site_data['is_phishing'] == 1 else 0,
        }
        
        # Se è stato fornito un percorso per il CSV dei risultati, aggiornalo
        if results_csv_path and lock:
            with lock:
                result_df = pd.DataFrame([result_data])
                # Controlla se il file esiste
                if os.path.exists(results_csv_path):
                    # Apri in modo append
                    result_df.to_csv(results_csv_path, mode='a', header=False, index=False)
                else:
                    # Crea il file con l'header
                    result_df.to_csv(results_csv_path, index=False)

        return result_data
    return None

def batch_capture_screenshots_parallel(sites_csv, config, max_workers=8):
    """Cattura gli screenshot dei siti in parallelo"""
    sites_df = pd.read_csv(sites_csv)
    
    # Prepara le cartelle
    screenshots_dir = os.path.join(config['paths']['data'], 'raw', 'screenshots')
    results_dir = os.path.join(config['paths']['results'])
    legit_dir = os.path.join(screenshots_dir, 'legit')
    phish_dir = os.path.join(screenshots_dir, 'phishing')
    os.makedirs(legit_dir, exist_ok=True)
    os.makedirs(phish_dir, exist_ok=True)
    
    # Percorso del CSV dei risultati
    results_csv_path = os.path.join(results_dir, 'screenshot_results.csv')
    
    # Se il CSV esiste già, carichiamolo per vedere quali sono già stati processati
    processed_sites = set()
    if os.path.exists(results_csv_path):
        try:
            existing_df = pd.read_csv(results_csv_path)
            # Creiamo una chiave unica con domain + hash_id per ogni screenshot già processato
            processed_sites = set(existing_df['domain'] + '_' + existing_df['hash_id'].astype(str))
        except Exception as e:
            logging.warning(f"Errore nel leggere il CSV esistente: {e}")
    
    # Filtriamo i siti non ancora processati
    sites_to_process = []
    for _, row in sites_df.iterrows():
        site_id = hashlib.md5(row['url'].encode()).hexdigest()[:8]
        if f"{row['domain']}_{site_id}" not in processed_sites:
            sites_to_process.append(row.to_dict())
    
    if not sites_to_process:
        logging.info("Tutti i siti sono già stati processati.")
        return results_csv_path
        
    logging.info(f"Processando {len(sites_to_process)} siti di {len(sites_df)} totali")
    
    # Creiamo un lock per thread-safety quando scriviamo sul file CSV
    import threading
    csv_lock = threading.Lock()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_site, site, config, results_csv_path, csv_lock) 
                  for site in sites_to_process]

        for future in concurrent.futures.as_completed(futures):
            try:
                # Processiamo il risultato ma non serve più salvarlo in una lista
                future.result()
            except Exception as e:
                logging.error(f"Errore durante il processo: {e}")

    return results_csv_path