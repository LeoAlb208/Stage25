import pandas as pd
import os
import hashlib
import glob

def merge_and_save_sites(legit_path, phish_path, output_path):
    """
    Merge legitimate and phishing sites into a single CSV file
    
    Args:
        legit_path (str): Path to legitimate sites CSV
        phish_path (str): Path to phishing sites CSV
        output_path (str): Path where to save the merged CSV
    """
    # Read the CSV files
    legit_sites = pd.read_csv(legit_path)
    phish_sites = pd.read_csv(phish_path)

    # Add phishing indicator column (0 for legitimate, 1 for phishing)
    legit_sites['is_phishing'] = 0
    phish_sites['is_phishing'] = 1

    # Concatenate the two dataframes
    combined_df = pd.concat([legit_sites, phish_sites], ignore_index=True)

    # Shuffle the dataset randomly
    shuffled_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Save the output
    shuffled_df.to_csv(output_path, index=False)

def merge_and_save_html_features(legit_numeric_path, phish_numeric_path, output_path):
    """
    Merge HTML numeric features from legitimate and phishing sites into a single CSV file
    
    Args:
        legit_numeric_path (str): Path to legitimate sites HTML numeric features CSV
        phish_numeric_path (str): Path to phishing sites HTML numeric features CSV 
        output_path (str): Path where to save the merged CSV
    """
    # Read the CSV files
    legit_features = pd.read_csv(legit_numeric_path)
    phish_features = pd.read_csv(phish_numeric_path)

    # Add phishing indicator column (0 for legitimate, 1 for phishing)
    legit_features['is_phishing'] = 0
    phish_features['is_phishing'] = 1

    # Concatenate the two dataframes
    combined_df = pd.concat([legit_features, phish_features], ignore_index=True)

    # Shuffle the dataset randomly
    shuffled_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Save the output
    shuffled_df.to_csv(output_path, index=False)

def merge_and_save_screenshot_data(legit_dir, phish_dir, output_path):
    """
    Create a CSV file with details about the screenshots in the legit and phishing directories
    
    Args:
        legit_dir (str): Directory with legitimate website screenshots
        phish_dir (str): Directory with phishing website screenshots
        output_path (str): Path where to save the CSV file
    """
    # Get all screenshot files
    legit_files = glob.glob(os.path.join(legit_dir, '*.png'))
    phish_files = glob.glob(os.path.join(phish_dir, '*.png'))
    
    # Create dataframes for legitimate and phishing screenshots
    legit_data = []
    for file_path in legit_files:
        domain = os.path.basename(file_path).split('_')[0]
        hash_id = os.path.basename(file_path).split('_')[1].split('.')[0] if '_' in os.path.basename(file_path) else ''
        legit_data.append({
            'screenshot_path': file_path,
            'domain': domain,
            'hash_id': hash_id,
            'is_phishing': 0,
        })
    
    phish_data = []
    for file_path in phish_files:
        domain = os.path.basename(file_path).split('_')[0]
        hash_id = os.path.basename(file_path).split('_')[1].split('.')[0] if '_' in os.path.basename(file_path) else ''
        phish_data.append({
            'screenshot_path': file_path,
            'domain': domain, 
            'hash_id': hash_id,
            'is_phishing': 1,
        })
    
    # Convert to dataframes
    legit_df = pd.DataFrame(legit_data)
    phish_df = pd.DataFrame(phish_data)
    
    # Combine the dataframes
    combined_df = pd.concat([legit_df, phish_df], ignore_index=True)
    
    # Shuffle the dataset randomly
    shuffled_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Save the output
    shuffled_df.to_csv(output_path, index=False)
    
    return shuffled_df

if __name__ == "__main__":
    # When run as script, use default paths
    current_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(os.path.dirname(current_dir), 'data', 'results')
    
    legit_path = os.path.join(results_dir, 'legit_sites.csv')
    phish_path = os.path.join(results_dir, 'phish_sites.csv')
    output_path = os.path.join(results_dir, 'sites.csv')
    
    merge_and_save_sites(legit_path, phish_path, output_path)

    processed_dir = os.path.join(os.path.dirname(current_dir), 'data', 'processed')
    training_dir = os.path.join(os.path.dirname(current_dir), 'data', 'trainingdata')
    
    legit_numeric_path = os.path.join(processed_dir, 'html_legit_numeric.csv')
    phish_numeric_path = os.path.join(processed_dir, 'html_phishing_numeric.csv')
    html_features_path = os.path.join(training_dir, 'html_features.csv')
    
    merge_and_save_html_features(legit_numeric_path, phish_numeric_path, html_features_path)
    
    # Merge screenshot data
    raw_dir = os.path.join(os.path.dirname(current_dir), 'data', 'raw')
    legit_screenshots_dir = os.path.join(raw_dir, 'screenshots', 'legit')
    phish_screenshots_dir = os.path.join(raw_dir, 'screenshots', 'phishing')
    screenshots_csv = os.path.join(raw_dir, 'screenshots', 'screenshot_results.csv')
    
    # Make sure the screenshots directory exists
    os.makedirs(os.path.join(raw_dir, 'screenshots'), exist_ok=True)
    
    merge_and_save_screenshot_data(legit_screenshots_dir, phish_screenshots_dir, screenshots_csv)