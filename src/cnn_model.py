import os
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras import layers, models, applications, optimizers
from tensorflow.keras.preprocessing.image import ImageDataGenerator
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import logging
import shutil
# Import the merge_and_save_screenshot_data function
from src.merge_results_csvs import merge_and_save_screenshot_data

# Setup logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PhishingScreenshotClassifier:
    def __init__(self, input_shape=(224, 224, 3), base_model='resnet50'):
        """
        Initialize the CNN model for phishing screenshot classification
        
        Args:
            input_shape (tuple): Input shape for the model (height, width, channels)
            base_model (str): Base model to use ('resnet50', 'vgg16', 'mobilenet')
        """
        self.input_shape = input_shape
        self.base_model_name = base_model
        self.model = self._build_model()
        
    def _build_model(self):
        """
        Build the CNN model architecture using transfer learning
        
        Returns:
            tf.keras.Model: Compiled model
        """
        # Create base model with pretrained weights
        if self.base_model_name == 'resnet50':
            base_model = applications.ResNet50(
                weights='imagenet', 
                include_top=False, 
                input_shape=self.input_shape
            )
        elif self.base_model_name == 'vgg16':
            base_model = applications.VGG16(
                weights='imagenet', 
                include_top=False, 
                input_shape=self.input_shape
            )
        elif self.base_model_name == 'mobilenet':
            base_model = applications.MobileNetV2(
                weights='imagenet', 
                include_top=False, 
                input_shape=self.input_shape
            )
        else:
            raise ValueError(f"Unsupported base model: {self.base_model_name}")
        
        # Freeze the base model layers
        base_model.trainable = False
        
        # Build the model on top of the base model
        model = models.Sequential([
            base_model,
            layers.GlobalAveragePooling2D(),
            layers.Dense(1024, activation='relu'),  # Layer più ampio
            layers.BatchNormalization(),  # Aggiunto normalizzazione
            layers.Dropout(0.5),
            layers.Dense(512, activation='relu'),
            layers.BatchNormalization(),  # Aggiunto normalizzazione
            layers.Dropout(0.4),
            layers.Dense(128, activation='relu'),  # Layer aggiuntivo
            layers.Dropout(0.3),
            layers.Dense(1, activation='sigmoid')
        ])
        
        # Sblocca gli ultimi layer del modello base per fine-tuning
        for layer in base_model.layers[-10:]:
            layer.trainable = True
        
        # Compile con learning rate più alto
        model.compile(
            optimizer=optimizers.Adam(learning_rate=5e-4),
            loss='binary_crossentropy',
            metrics=['accuracy', tf.keras.metrics.AUC(name='auc')]
        )
        
        return model
    
    def train(self, train_dir, valid_dir=None, batch_size=32, epochs=10, valid_split=0.2):
        """
        Train the model using data generators
        
        Args:
            train_dir (str): Directory with training data
            valid_dir (str): Directory with validation data (optional)
            batch_size (int): Batch size
            epochs (int): Number of epochs
            valid_split (float): Validation split if valid_dir not provided
            
        Returns:
            dict: Training history
        """
        # Più data augmentation
        train_datagen = ImageDataGenerator(
            rescale=1./255,
            rotation_range=30,
            width_shift_range=0.3,
            height_shift_range=0.3,
            shear_range=0.3,
            zoom_range=0.3,
            horizontal_flip=True,
            vertical_flip=True,  # Aggiunto flip verticale
            brightness_range=[0.8, 1.2],  # Aggiunta variazione luminosità
            fill_mode='nearest',
            validation_split=valid_split if valid_dir is None else 0
        )
        
        # Just rescaling for validation
        valid_datagen = ImageDataGenerator(rescale=1./255)
        
        # Flow from directory - training
        train_generator = train_datagen.flow_from_directory(
            train_dir,
            target_size=self.input_shape[:2],
            batch_size=batch_size,
            class_mode='binary',
            subset='training' if valid_dir is None else None
        )
        
        # Validation generator
        if valid_dir is None:
            valid_generator = train_datagen.flow_from_directory(
                train_dir,
                target_size=self.input_shape[:2],
                batch_size=batch_size,
                class_mode='binary',
                subset='validation'
            )
        else:
            valid_generator = valid_datagen.flow_from_directory(
                valid_dir,
                target_size=self.input_shape[:2],
                batch_size=batch_size,
                class_mode='binary'
            )
        
        # Callbacks
        callbacks = [
            tf.keras.callbacks.EarlyStopping(
                monitor='val_loss', patience=5, restore_best_weights=True
            ),
            tf.keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss', factor=0.2, patience=3, min_lr=1e-6
            )
        ]
        
        # Class weights
        class_weights = {0: 1.0, 1: len(train_generator.classes == 0) / len(train_generator.classes == 1)}
        
        # Train the model
        history = self.model.fit(
            train_generator,
            epochs=epochs,
            validation_data=valid_generator,
            callbacks=callbacks,
            class_weight=class_weights  # Aggiunto qui
        )
        
        return history.history
    
    def evaluate(self, test_dir, batch_size=32):
        """
        Evaluate the model on test data
        
        Args:
            test_dir (str): Directory with test data
            batch_size (int): Batch size
            
        Returns:
            dict: Evaluation metrics
        """
        # Data generator for test data
        test_datagen = ImageDataGenerator(rescale=1./255)
        
        # Test generator
        test_generator = test_datagen.flow_from_directory(
            test_dir,
            target_size=self.input_shape[:2],
            batch_size=batch_size,
            class_mode='binary',
            shuffle=False
        )
        
        # Evaluate
        results = self.model.evaluate(test_generator)
        
        # Get predictions
        predictions = self.model.predict(test_generator)
        y_pred = (predictions > 0.5).astype(int).flatten()
        y_true = test_generator.classes
        
        # Classification report and confusion matrix
        report = classification_report(y_true, y_pred, output_dict=True)
        cm = confusion_matrix(y_true, y_pred)
        
        return {
            'loss': results[0],
            'accuracy': results[1],
            'auc': results[2],
            'classification_report': report,
            'confusion_matrix': cm
        }
    
    def save(self, path):
        """
        Save the model
        
        Args:
            path (str): Path to save the model
        """
        self.model.save(path)
        logger.info(f"Model saved to {path}")
    
    def load(self, path):
        """
        Load a saved model
        
        Args:
            path (str): Path to the saved model
        """
        self.model = tf.keras.models.load_model(path)
        logger.info(f"Model loaded from {path}")

def prepare_screenshot_data(screenshots_csv, test_screenshots_csv, output_dir):
    """
    Prepare screenshots for training and testing. Uses the main dataset for
    training/validation and a separate dataset for testing.

    Args:
        screenshots_csv (str): Path to CSV with main screenshot information (for train/valid)
        test_screenshots_csv (str): Path to CSV with test screenshot information
        output_dir (str): Directory to save organized data

    Returns:
        dict: Paths to train, validation, and test directories
    """
    # Load the main screenshots data for training and validation
    df_main = pd.read_csv(screenshots_csv)
    if not all(col in df_main.columns for col in ['screenshot_path', 'is_phishing']):
        raise ValueError(f"Main CSV {screenshots_csv} must contain 'screenshot_path' and 'is_phishing' columns.")

    # Load the test screenshots data
    df_test = pd.read_csv(test_screenshots_csv)
    if not all(col in df_test.columns for col in ['screenshot_path', 'is_phishing']):
        raise ValueError(f"Test CSV {test_screenshots_csv} must contain 'screenshot_path' and 'is_phishing' columns.")

    # Create output directories
    train_dir = os.path.join(output_dir, 'train')
    valid_dir = os.path.join(output_dir, 'valid')
    test_dir = os.path.join(output_dir, 'test')

    for dir_path in [train_dir, valid_dir, test_dir]:
        os.makedirs(os.path.join(dir_path, 'phishing'), exist_ok=True)
        os.makedirs(os.path.join(dir_path, 'legit'), exist_ok=True)

    # Split main data into train and validation (e.g., 80/20 split)
    # Using the entire main dataset for training and validation pool
    train_df, valid_df = train_test_split(df_main, test_size=0.2, stratify=df_main['is_phishing'], random_state=42)

    # The test data comes directly from the test CSV
    test_df = df_test

    # Function to copy files to appropriate directories
    def copy_files(dataframe, target_dir):
        copied_count = 0
        skipped_count = 0
        for _, row in dataframe.iterrows():
            src_path = row['screenshot_path']
            # Ensure the path exists before copying
            if not os.path.exists(src_path):
                logger.warning(f"Source file not found, skipping: {src_path}")
                skipped_count += 1
                continue

            # Determine destination subdirectory based on 'is_phishing'
            dst_subdir = 'phishing' if row['is_phishing'] else 'legit'
            # Construct the full destination path
            dst_path = os.path.join(target_dir, dst_subdir, os.path.basename(src_path))

            # Copy the file, preserving metadata
            try:
                shutil.copy2(src_path, dst_path)
                copied_count += 1
            except Exception as e:
                logger.error(f"Failed to copy {src_path} to {dst_path}: {e}")
                skipped_count += 1
        logger.info(f"Copied {copied_count} files to {target_dir}, skipped {skipped_count} files.")


    # Copy files to respective directories
    logger.info("Copying training files...")
    copy_files(train_df, train_dir)
    logger.info("Copying validation files...")
    copy_files(valid_df, valid_dir)
    logger.info("Copying test files...")
    copy_files(test_df, test_dir) # Use the separate test dataframe

    logger.info(f"Data preparation complete: {len(train_df)} training, {len(valid_df)} validation, {len(test_df)} test samples")

    return {
        'train_dir': train_dir,
        'valid_dir': valid_dir,
        'test_dir': test_dir
    }

def train_cnn_model(config):
    """
    Train the CNN model for phishing detection

    Args:
        config (dict): Configuration dictionary

    Returns:
        dict: Model evaluation results
    """

    # Paths
    raw_screenshots_dir = os.path.join(config['paths']['data'], 'raw', 'screenshots')
    results_dir = os.path.join(config['paths']['results'])
    legit_screenshots_dir = os.path.join(raw_screenshots_dir, 'legit')
    phish_screenshots_dir = os.path.join(raw_screenshots_dir, 'phishing')
    # Main CSV for training/validation
    screenshots_csv = os.path.join(results_dir, 'screenshot_results.csv')
    # Separate CSV for testing
    test_screenshots_csv = os.path.join(results_dir, 'test_screenshot_results.csv') # Added path for test CSV
    processed_dir = os.path.join(config['paths']['data'], 'processed', 'screenshots_split') # Changed output dir slightly to avoid conflicts if run multiple times
    model_dir = os.path.join(config['paths']['models'], 'cnn')

    # Create directories
    os.makedirs(processed_dir, exist_ok=True)
    os.makedirs(model_dir, exist_ok=True)

    # Ensure the main screenshot results CSV exists (or create it)
    if not os.path.exists(screenshots_csv):
        logger.info(f"Main screenshot CSV {screenshots_csv} not found. Creating it...")
        merge_and_save_screenshot_data(
            legit_screenshots_dir,
            phish_screenshots_dir,
            screenshots_csv
        )
        logger.info(f"Main screenshot data merged and saved to {screenshots_csv}")
    else:
         logger.info(f"Using existing main screenshot CSV: {screenshots_csv}")

    # Ensure the test screenshot results CSV exists
    if not os.path.exists(test_screenshots_csv):
         # If the test CSV doesn't exist, we cannot proceed with the requested setup.
         # You might need to run the screenshot capture/processing for the test set first.
         logger.error(f"Test screenshot CSV {test_screenshots_csv} not found. Please ensure it exists.")
         raise FileNotFoundError(f"Required test screenshot CSV not found: {test_screenshots_csv}")
    else:
        logger.info(f"Using existing test screenshot CSV: {test_screenshots_csv}")


    # Prepare data using the modified function
    data_paths = prepare_screenshot_data(screenshots_csv, test_screenshots_csv, processed_dir)

    # Initialize model
    model = PhishingScreenshotClassifier(
        input_shape=(224, 224, 3),
        base_model=config.get('cnn', {}).get('base_model', 'resnet50')
    )

    # Train model - Note: valid_split in train_datagen is now ignored because valid_dir is provided
    history = model.train(
        train_dir=data_paths['train_dir'],
        valid_dir=data_paths['valid_dir'], # Pass the specific validation directory
        batch_size=config.get('cnn', {}).get('batch_size', 32),
        epochs=config.get('cnn', {}).get('epochs', 20),
        valid_split=0 # Explicitly set to 0 as we provide valid_dir
    )

    # Evaluate model using the dedicated test set
    evaluation = model.evaluate(data_paths['test_dir'])

    # Save model
    model_path = os.path.join(model_dir, 'phishing_cnn_model.h5')
    model.save(model_path)

    # Save training history
    history_df = pd.DataFrame(history)
    history_df.to_csv(os.path.join(model_dir, 'training_history.csv'), index=False)

    # Plot training history (ensure keys exist before plotting)
    plt.figure(figsize=(12, 4))

    if 'accuracy' in history and 'val_accuracy' in history:
        plt.subplot(1, 2, 1)
        plt.plot(history['accuracy'], label='Train Accuracy')
        plt.plot(history['val_accuracy'], label='Validation Accuracy')
        plt.title('Model Accuracy')
        plt.xlabel('Epoch')
        plt.ylabel('Accuracy')
        plt.legend()
    else:
        logger.warning("Accuracy keys not found in history for plotting.")


    if 'loss' in history and 'val_loss' in history:
        plt.subplot(1, 2, 2)
        plt.plot(history['loss'], label='Train Loss')
        plt.plot(history['val_loss'], label='Validation Loss')
        plt.title('Model Loss')
        plt.xlabel('Epoch')
        plt.ylabel('Loss')
        plt.legend()
    else:
        logger.warning("Loss keys not found in history for plotting.")


    plt.tight_layout()
    plt.savefig(os.path.join(model_dir, 'training_history.png'))

    # Return the evaluation and paths
    return {
        'evaluation': evaluation,
        'model_path': model_path,
        'history_path': os.path.join(model_dir, 'training_history.csv')
    }