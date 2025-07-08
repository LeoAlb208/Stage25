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

def capture_screenshot(url, output_path, max_height=15000, verbose=False, timeout=10):
    """
    Capture a screenshot of a webpage using SeleniumBase.
    Scrolls to capture the entire page up to max_height pixels.
    
    Args:
        url: The URL to capture
        output_path: Where to save the screenshot
        max_height: Maximum height in pixels to capture
        verbose: If True, prints additional debug information
    """
    if verbose:
        logging.info(f"Inizio cattura screenshot per {url}")
        logging.info(f"Dimensione massima: {max_height}px, Output: {output_path}")

    driver = Driver(uc=True, headless= not verbose, extension_dir="src\Idontcarecookies")
    driver.set_page_load_timeout(timeout)
    
    try:
        if verbose:
            logging.info(f"Aprendo URL: {url}")
        driver.get(url)
        time.sleep(1.5)  # Attende il caricamento iniziale
        
        # Ottieni le dimensioni della pagina
        total_height = driver.execute_script("return document.body.scrollHeight")
        total_height = min(total_height, max_height)  # Limita l'altezza massima
        
        if verbose:
            logging.info(f"Altezza pagina: {total_height}px")
        
        # Imposta la dimensione della finestra per catturare l'intera larghezza
        viewport_width = driver.execute_script("return document.documentElement.clientWidth")
        driver.set_window_size(viewport_width, total_height)
        
        if verbose:
            logging.info(f"Dimensione finestra impostata a {viewport_width}x{total_height}")
        
        # Scroll lentamente fino in fondo per caricare contenuti lazy-loaded
        current_height = 0
        while current_height < total_height:
            driver.execute_script(f"window.scrollTo(0, {current_height});")
            current_height += 500
            if verbose and current_height % 1000 == 0:
                logging.info(f"Scrolling: {current_height}/{total_height}px")
            time.sleep(0.2)
        
        # Torna all'inizio e cattura lo screenshot
        if verbose:
            logging.info("Tornando all'inizio della pagina e preparando screenshot")
        driver.execute_script("window.scrollTo(0, 0);")
        time.sleep(0.3)  # Attende eventuali animazioni
        driver.save_screenshot(output_path)
        
        if os.path.exists(output_path):
            if verbose:
                logging.info(f"✅ Screenshot salvato: {output_path}")
                file_size = os.path.getsize(output_path) / 1024  # KB
                logging.info(f"Dimensione file: {file_size:.2f} KB")
            return True
        else:
            if verbose:
                logging.error(f"Il file non esiste dopo il tentativo di salvataggio: {output_path}")
            return False
        
    except Exception as e:
        logging.error(f"❌ Errore su {url}")
        if verbose:
            logging.exception(f"Dettaglio errore: {str(e)}")
        return False
    finally:
        if verbose:
            logging.info("Chiusura driver browser")
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

def process_site(site_data, output_dir, results_csv_path=None, lock=None, verbose=False):
    """Processa un singolo sito e ne cattura lo screenshot"""
    url = site_data[1]
    filename = generate_screenshot_filename(url)
    output_path = os.path.join(output_dir, filename)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    if os.path.exists(output_path):
        return {'url': url, 'screenshot_path': output_path, 'success': True}

    screenshot_path = None

    for attempt in range(3):
        try:
            success = capture_screenshot(url, output_path, verbose=verbose)
            if success:
                screenshot_path = output_path
                break
            time.sleep(attempt * 2)  # Exponential backoff
        except Exception as e:
            logging.error(f"Tentativo {attempt + 1} fallito per {url}")
    #success = capture_screenshot(url, output_path, verbose=verbose)
    if success:
        screenshot_path = output_path
    else:
        if verbose: logging.error(f"Non è stato possibile catturare lo screenshot per {url}")
    if screenshot_path:
        result_data = {
            'ogidx': site_data[0],  # Assuming site_data is a tuple (ogidx, url)
            'screenshot_path': screenshot_path,
            'url': site_data,
            'hash_id': hashlib.md5(url.encode()).hexdigest()[:8],
        }

        if results_csv_path and lock:
            with lock:
                result_df = pd.DataFrame([result_data])
                if os.path.exists(results_csv_path):
                    result_df.to_csv(results_csv_path, mode='a', header=False, index=False)
                else:
                    result_df.to_csv(results_csv_path, index=False)

        return result_data
    else:
        return {'url': url, 'success': False}


def capture_single_screenshot(url, output_dir, output_filename=None, results_csv_path=None, verbose=False):
    """
    Captures a screenshot for a single URL and saves it to the specified directory
    without depending on whether it's phishing or legitimate.
    
    Args:
        url: The URL to capture
        output_dir: Directory where to save the screenshot
        output_filename: Optional custom filename, if None will be auto-generated
        results_csv_path: Optional path to a CSV file to record the result
        verbose: If True, prints additional debug information
    
    Returns:
        Dict with the result information
    """
    if verbose:
        logging.info(f"Starting screenshot capture for {url}")
        
    if not output_filename:
        output_filename = generate_screenshot_filename(url)
        if verbose:
            logging.info(f"Generated filename: {output_filename}")
    
    output_path = os.path.join(output_dir, output_filename)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
    if os.path.exists(output_path):
        logging.info(f"Screenshot already exists for {url}")
        result_data = {
            'url': url,
            'screenshot_path': output_path, 
            'success': True,
            'domain': urlparse(url).netloc,
            'hash_id': hashlib.md5(url.encode()).hexdigest()[:8]
        }
        
        # Aggiorna il CSV se richiesto
        if results_csv_path:
            if verbose:
                logging.info(f"Updating results CSV: {results_csv_path}")
            _update_results_csv(result_data, results_csv_path)
            
        return result_data
        
    for attempt in range(3):
        if verbose:
            logging.info(f"Attempt {attempt + 1}/3 for {url}")
        try:
            success = capture_screenshot(url, output_path)
            if success:
                if verbose:
                    logging.info(f"Successfully captured screenshot for {url}")
                result_data = {
                    'url': url,
                    'screenshot_path': output_path,
                    'success': True,
                    'domain': urlparse(url).netloc,
                    'hash_id': hashlib.md5(url.encode()).hexdigest()[:8]
                }
                
                # Aggiorna il CSV se richiesto
                if results_csv_path:
                    if verbose:
                        logging.info(f"Updating results CSV with successful capture: {results_csv_path}")
                    _update_results_csv(result_data, results_csv_path)
                    
                return result_data
            if verbose:
                logging.info(f"Attempt {attempt + 1} failed, retrying after delay")
            time.sleep(attempt * 2)  # Exponential backoff
        except Exception as e:
            logging.error(f"Attempt {attempt + 1} failed for {url}: {e}")
            if verbose:
                logging.exception("Detailed error information:")
        
    logging.warning(f"All attempts failed for {url}")
    return {'url': url, 'success': False}

def _update_results_csv(result_data, results_csv_path):
    """Helper function to update the results CSV"""
    import pandas as pd
    import os
    
    result_df = pd.DataFrame([result_data])
    # Controlla se il file esiste
    if os.path.exists(results_csv_path):
        # Apri in modo append
        result_df.to_csv(results_csv_path, mode='a', header=False, index=False)
    else:
        # Crea il file con l'header
        result_df.to_csv(results_csv_path, index=False)
def batch_capture_screenshots_parallel(sites_to_process, output_dir, results_dir, verbose=False, max_workers=8):
    """Cattura gli screenshot dei siti in parallelo, salvandoli tutti nella directory output_dir"""

    # Assicuriamoci che la directory di output esista
    os.makedirs(output_dir, exist_ok=True)

    os.makedirs(results_dir, exist_ok=True)
    # Percorso del CSV dei risultati
    results_csv_path = os.path.join(results_dir, 'screenshot_results.csv')

    if verbose: logging.info(f"Processando {len(sites_to_process)} siti in parallelo...")

    import threading
    csv_lock = threading.Lock()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(process_site, site, output_dir, results_csv_path, csv_lock, verbose)
            for site in sites_to_process.items()
        ]

        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                if verbose: logging.error(f"Errore durante il processo: {e}")

    return results_csv_path
