import os
import pandas as pd
from bs4 import BeautifulSoup
from bs4 import XMLParsedAsHTMLWarning
import warnings
from urllib.parse import urlparse, urljoin
import re
import langdetect  # Nuovo import per il rilevamento della lingua

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

def parse_html(file_path):
    """
    Esegue il parsing di un file HTML estraendo elementi strutturali e contenuto.
    """
    # Inizializza il risultato con valori di default
    result = {
        "f56_https_resources": 0,
        "f57_http_resources": 0,
        "f58_external_domains_count": 0,
        "f59_relative_urls": 0,
        "f60_inline_scripts": 0,
        "f61_external_scripts": 0,
        "f62_password_inputs": 0,
        "f63_hidden_inputs": 0,
        "f64_forms_count": 0,
        "f65_iframe_count": 0,
        "f66_images_count": 0,
        "f67_links_count": 0,
        "f68_redirect_meta": 0,  # Convertito da bool a int
        "f69_language_mismatch": 0,  # Convertito da bool a int
        "f70_h1_count": 0,
        "f71_h2_count": 0,
        "f72_js_cookies_set": 0,
        "f73_js_cookies_read": 0,
        "f74_total_cookies": 0,
        "f75_input_fields_total": 0,
        "f76_input_fields_without_labels": 0,
        "f77_input_fields_suspicious_names": 0,
        "f78_favicon_mismatch": 0,  # Convertito da bool a int
        "f79_logo_count": 0,
        "f80_has_ssl_seal": 0,  # Convertito da bool a int
        "f81_has_copyright": 0,  # Convertito da bool a int
        "f82_data_uri_count": 0,
        "f83_javascript_uri_count": 0,
        "f84_urgent_words_count": 0,
        "f85_form_action_external": 0,  # Convertito da bool a int
        "f86_password_related_words": 0,
        "f87_security_related_words": 0,
        "f88_dom_depth": 0,
        "f89_dom_nodes": 0,
        "f90_dom_leaf_ratio": 0.0,
        "f91_external_css": 0,
        "f92_inline_styles": 0,
        "f93_style_tags": 0,
        "f94_inline_events": 0,
        "f95_obfuscated_events": 0,
        "f96_internal_resources": 0,
        "f97_external_resources": 0,
        "f98_external_resource_ratio": 0.0
    }

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
        soup = BeautifulSoup(content, "html.parser")

    # Rimuovo Base features non numeriche
    # (rimuovo le righe relative a title e description)
    
    # Mixed content analysis
    mixed_content = _check_mixed_content(soup)
    result["f56_https_resources"] = mixed_content["https"]
    result["f57_http_resources"] = mixed_content["http"]
    
    # URLs and resources analysis
    result["f58_external_domains_count"] = len(_extract_suspicious_domains(soup))
    # rimuovo external_domains_list perché non numerica
    result["f59_relative_urls"] = len([link for link in soup.find_all(['a', 'img', 'script', 'link']) 
                        if link.get('href','').startswith('//') or link.get('src','').startswith('//')])
    
    # Scripts analysis
    result["f60_inline_scripts"] = len(soup.find_all("script", string=True))
    result["f61_external_scripts"] = len(soup.find_all("script", src=True))
    
    # DOM Complexity Analysis (dopo Base features)
    dom_stats = _analyze_dom_complexity(soup)
    result["f88_dom_depth"] = dom_stats["max_depth"]
    result["f89_dom_nodes"] = dom_stats["total_nodes"]
    result["f90_dom_leaf_ratio"] = dom_stats["leaf_nodes"] / dom_stats["total_nodes"] if dom_stats["total_nodes"] > 0 else 0
    
    # Form elements analysis
    result["f62_password_inputs"] = len(soup.find_all("input", type="password"))
    result["f63_hidden_inputs"] = len(soup.find_all("input", type="hidden"))
    result["f64_forms_count"] = len(soup.find_all("form"))
    
    # CSS Analysis (dopo Scripts analysis)
    css_stats = _analyze_css_usage(soup)
    result["f91_external_css"] = css_stats["external_css_count"]
    result["f92_inline_styles"] = css_stats["inline_styles_count"]
    result["f93_style_tags"] = css_stats["style_tags_count"]
    
    # Other elements
    result["f65_iframe_count"] = len(soup.find_all("iframe"))
    result["f66_images_count"] = len(soup.find_all("img"))
    result["f67_links_count"] = len(soup.find_all("a"))
    
    # Meta redirects
    result["f68_redirect_meta"] = int(bool(soup.find("meta", attrs={"http-equiv": "refresh"})))
    
    # Language analysis
    lang_analysis = _check_language_mismatch(soup)
    result["f69_language_mismatch"] = int(lang_analysis["has_mismatch"])
    # rimuovo declared_language e detected_language perché non numeriche
    
    # Headers analysis
    headers = _analyze_headers(soup)
    result["f70_h1_count"] = headers["count"]["h1"]
    result["f71_h2_count"] = headers["count"]["h2"]
    
    # Cookie analysis
    cookies = _find_cookies(content)
    result["f72_js_cookies_set"] = len(cookies["js_set"])
    result["f73_js_cookies_read"] = len(cookies["js_read"])
    result["f74_total_cookies"] = cookies["total_count"]
    
    # Input field analysis
    input_analysis = _analyze_input_fields(soup)
    result["f75_input_fields_total"] = input_analysis["total"]
    result["f76_input_fields_without_labels"] = input_analysis["unlabeled"]
    result["f77_input_fields_suspicious_names"] = input_analysis["suspicious_names"]
    
    # Event Analysis (dopo Form elements analysis)
    events = _analyze_inline_events(soup)
    result["f94_inline_events"] = events["events_count"]
    result["f95_obfuscated_events"] = events["obfuscated_events"]
    
    # Brand impersonation
    result["f78_favicon_mismatch"] = int(_check_favicon_mismatch(soup))
    result["f79_logo_count"] = len(soup.find_all("img", {"src": re.compile(r"logo", re.I)}))
    
    # Security indicators
    result["f80_has_ssl_seal"] = int(bool(soup.find_all("img", {"src": re.compile(r"(ssl|secure|norton|mcafee)", re.I)})))
    result["f81_has_copyright"] = int(bool(re.search(r'©|copyright|all rights reserved', content, re.I)))
    
    # URL manipulation
    result["f82_data_uri_count"] = len([x for x in soup.find_all() if x.get('href', '').startswith('data:')])
    result["f83_javascript_uri_count"] = len([x for x in soup.find_all() if x.get('href', '').startswith('javascript:')])
    
    # Resource Analysis (dopo URL manipulation)
    resources = _analyze_resource_origins(soup)
    result["f96_internal_resources"] = resources["internal_resources"]
    result["f97_external_resources"] = resources["external_resources"]
    result["f98_external_resource_ratio"] = resources["external_ratio"]
    
    # Content analysis
    result["f84_urgent_words_count"] = len(re.findall(r'urgent|immediate|suspended|verify|blocked|limited', content, re.I))
    result["f85_form_action_external"] = int(any(form.get('action', '').startswith(('http', '//')) for form in soup.find_all('form')))
    
    # Social engineering
    result["f86_password_related_words"] = len(re.findall(r'password|passwd|pwd|credentials', content, re.I))
    result["f87_security_related_words"] = len(re.findall(r'security|secure|protection|verify', content, re.I))
    
    return result

def parse_html_text(file_path):
    """
    Esegue il parsing di un file HTML estraendo solo elementi testuali.
    
    Args:
        file_path (str): Percorso al file HTML
    
    Returns:
        dict: Dizionario contenente le feature testuali
    """
    # Inizializza il risultato con valori di default
    result = {
        "filename": os.path.basename(file_path),
        "title": "",
        "description": "",
        "external_domains_list": []
    }

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
        soup = BeautifulSoup(content, "html.parser")

    # Estrai il titolo
    title_tag = soup.find("title")
    if title_tag:
        result["title"] = title_tag.get_text(strip=True)

    # Estrai la descrizione
    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc:
        result["description"] = meta_desc.get("content", "")

    # Estrai domini esterni
    result["external_domains_list"] = _extract_suspicious_domains(soup)

    return result

def _check_mixed_content(soup):
    """Controlla la presenza di contenuti misti HTTP/HTTPS"""
    https_count = 0
    http_count = 0
    for tag in soup.find_all(['script', 'link', 'img', 'iframe']):
        src = tag.get('src') or tag.get('href')
        if src:
            if src.startswith('https://'):
                https_count += 1
            elif src.startswith('http://'):
                http_count += 1
    return {"https": https_count, "http": http_count}

def _extract_suspicious_domains(soup):
    """Estrae e analizza i domini sospetti"""
    domains = set()
    for tag in soup.find_all(['a', 'script', 'img', 'link', 'iframe']):
        url = tag.get('href') or tag.get('src')
        if url and (url.startswith('http') or url.startswith('//')):
            domain = urlparse(url if url.startswith('http') else f'http:{url}').netloc
            domains.add(domain)
    return list(domains)

def _check_language_mismatch(soup):
    """
    Controlla se c'è un mismatch tra la lingua dichiarata e il contenuto effettivo
    """
    try:
        # Ottiene la lingua dichiarata
        declared_lang = soup.html.get('lang', '').lower()
        if not declared_lang:
            return {"has_mismatch": False, "reason": "No language declared"}

        # Raccoglie il testo visibile
        visible_text = ' '.join([text for text in soup.stripped_strings])
        if len(visible_text) < 50:  # Skip if not enough text
            return {"has_mismatch": False, "reason": "Not enough text"}

        # Rileva la lingua del contenuto
        detected_lang = langdetect.detect(visible_text)

        # Controlla il mismatch
        has_mismatch = not detected_lang.startswith(declared_lang[:2])
        
        return {
            "has_mismatch": has_mismatch,
            "declared_lang": declared_lang,
            "detected_lang": detected_lang,
            "confidence": True  # langdetect non fornisce confidence score
        }
    except:
        return {"has_mismatch": False, "reason": "Language detection failed"}

def _analyze_headers(soup):
    """
    Analizza i tag header (h1, h2) e il loro contenuto
    """
    headers = {
        "h1": [],
        "h2": [],
        "count": {
            "h1": 0,
            "h2": 0
        }
    }
    
    # Analizza H1
    for h1 in soup.find_all('h1'):
        headers["h1"].append({
            "text": h1.get_text(strip=True),
            "is_visible": bool(h1.get_text(strip=True)),
            "has_links": bool(h1.find_all('a')),
            "length": len(h1.get_text(strip=True))
        })
        headers["count"]["h1"] += 1

    # Analizza H2
    for h2 in soup.find_all('h2'):
        headers["h2"].append({
            "text": h2.get_text(strip=True),
            "is_visible": bool(h2.get_text(strip=True)),
            "has_links": bool(h2.find_all('a')),
            "length": len(h2.get_text(strip=True))
        })
        headers["count"]["h2"] += 1

    return headers

def _find_cookies(content):
    """Analizza tutti i cookie nel documento"""
    cookies = {
        "js_set": [],      # Cookie impostati via JavaScript
        "js_read": [],     # Cookie letti via JavaScript
        "total_count": 0
    }
    
    # Cookie impostati via JavaScript
    set_patterns = [
        r'document\.cookie\s*=\s*["\']([^"\']+)["\']',           # document.cookie = '...'
        r'document\.cookie\.set\(["\']([^"\']+)["\']\)',         # document.cookie.set('...')
        r'setCookie\(["\']([^"\']+)["\']\)'                      # setCookie('...')
    ]
    
    for pattern in set_patterns:
        found = re.findall(pattern, content)
        cookies["js_set"].extend(found)
    
    # Cookie letti via JavaScript
    read_pattern = r'document\.cookie\.match\(["\']([^"\']+)["\']\)'
    cookies["js_read"] = re.findall(read_pattern, content)
    
    cookies["total_count"] = len(cookies["js_set"]) + len(cookies["js_read"])
    
    return cookies

def _analyze_input_fields(soup):
    """
    Analizza i campi di input nel documento
    """
    input_fields = soup.find_all("input")
    total = len(input_fields)
    unlabeled = len([inp for inp in input_fields if not inp.find_previous_sibling("label")])
    suspicious_names = len([inp for inp in input_fields if re.search(r'username|user|login|email|password|passwd|pwd', inp.get('name', ''), re.I)])
    
    return {
        "total": total,
        "unlabeled": unlabeled,
        "suspicious_names": suspicious_names
    }

def _check_favicon_mismatch(soup):
    """
    Controlla se il favicon è diverso dal dominio principale
    """
    # Cerca favicon con diversi valori di rel comuni
    favicons = soup.find_all("link", rel=["icon", "shortcut icon", "apple-touch-icon"])
    
    if not favicons:
        return False
    
    # Cerca il dominio principale in modo sicuro
    base_tag = soup.find("base")
    base_href = base_tag.get("href") if base_tag else ""
    main_domain = urlparse(base_href).netloc
    
    if not main_domain:
        return False
    
    # Controlla tutti i favicon trovati
    for favicon in favicons:
        favicon_url = favicon.get("href")
        if favicon_url and not favicon_url.startswith("/"):
            favicon_domain = urlparse(favicon_url).netloc
            if favicon_domain and favicon_domain != main_domain:
                return True
    
    return False

def _analyze_dom_complexity(soup):
    """
    Analizza la complessità del DOM
    """
    def _get_dom_depth(element, depth=0):
        if not element.children:
            return depth
        child_depths = [_get_dom_depth(child, depth + 1) 
                       for child in element.children 
                       if child.name]
        return max(child_depths) if child_depths else depth

    def _count_dom_nodes(element):
        return sum(1 for _ in element.descendants if _.name)

    def _count_leaf_nodes(element):
        return sum(1 for _ in element.descendants if _.name and not list(_.children))

    max_depth = _get_dom_depth(soup)
    total_nodes = _count_dom_nodes(soup)
    leaf_nodes = _count_leaf_nodes(soup)

    return {
        "max_depth": max_depth,
        "total_nodes": total_nodes,
        "leaf_nodes": leaf_nodes
    }

def _analyze_css_usage(soup):
    """
    Analizza l'uso del CSS nel documento
    """
    external_css_count = len(soup.find_all("link", rel="stylesheet"))
    inline_styles_count = len(soup.find_all(style=True))
    style_tags_count = len(soup.find_all("style"))

    return {
        "external_css_count": external_css_count,
        "inline_styles_count": inline_styles_count,
        "style_tags_count": style_tags_count
    }

def _analyze_inline_events(soup):
    """
    Analizza gli eventi inline nel documento
    """
    events_count = 0
    obfuscated_events = 0
    event_attributes = [
        "onclick", "onload", "onmouseover", "onfocus", "onerror", "onblur", "onchange", "onsubmit"
    ]

    for tag in soup.find_all(True):
        for attr in event_attributes:
            if tag.has_attr(attr):
                events_count += 1
                if re.search(r'[\x00-\x1F\x7F-\x9F]', tag[attr]):
                    obfuscated_events += 1

    return {
        "events_count": events_count,
        "obfuscated_events": obfuscated_events
    }

def _analyze_resource_origins(soup):
    """
    Analizza le origini delle risorse nel documento
    """
    internal_resources = 0
    external_resources = 0

    for tag in soup.find_all(['script', 'link', 'img', 'iframe']):
        src = tag.get('src') or tag.get('href')
        if src:
            if src.startswith(('http://', 'https://')):
                external_resources += 1
            else:
                internal_resources += 1

    total_resources = internal_resources + external_resources
    external_ratio = external_resources / total_resources if total_resources > 0 else 0

    return {
        "internal_resources": internal_resources,
        "external_resources": external_resources,
        "external_ratio": external_ratio
    }

def process_directory(input_folder, output_csv_numeric, output_csv_text, is_phishing=False):
    """
    Processa tutti i file HTML in una directory e salva i risultati in CSV separati per
    feature numeriche e testuali.
    
    Args:
        input_folder (str): Cartella contenente i file HTML
        output_csv_numeric (str): Percorso dove salvare il CSV con feature numeriche
        output_csv_text (str): Percorso dove salvare il CSV con feature testuali
        is_phishing (bool): Flag che indica se i campioni sono phishing
    
    Returns:
        tuple: (df_numeric, df_text) - I dataframes con feature numeriche e testuali
    """
    results_numeric = []
    results_text = []

    for filename in os.listdir(input_folder):
        if filename.endswith(".html"):
            file_path = os.path.join(input_folder, filename)
            # Estrae feature numeriche
            parsed_data_numeric = parse_html(file_path)
            parsed_data_numeric["is_phishing"] = is_phishing  # Aggiungiamo qui il flag
            results_numeric.append(parsed_data_numeric)
            
            # Estrae feature testuali
            parsed_data_text = parse_html_text(file_path)
            results_text.append(parsed_data_text)
    
    # Crea e salva DataFrame numerici
    df_numeric = pd.DataFrame(results_numeric)
    df_numeric.to_csv(output_csv_numeric, index=False)
    
    # Crea e salva DataFrame testuali
    df_text = pd.DataFrame(results_text)
    df_text.to_csv(output_csv_text, index=False)
    
    # Aggiungi questa riga per restituire i dataframes
    return df_numeric, df_text
