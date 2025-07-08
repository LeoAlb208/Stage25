import logging
import os
import yaml

def setup_logging(log_level=logging.INFO):
    """
    Configura il logging per il progetto.
    """
    logging.basicConfig(level=log_level,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logging.info("Logging configurato correttamente.")

def load_config(config_path):
    """
    Carica il file di configurazione YAML.
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Il file di configurazione {config_path} non esiste.")
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    return config
