from transformers import BertTokenizer, BertForSequenceClassification, logging
import torch
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
import warnings

# Disabilita i warning dei weights
logging.set_verbosity_error()

class BertPhishingClassifier:
    def __init__(self):
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore")
            self.tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
            self.tokenizer.add_special_tokens({'additional_special_tokens': ['[FILENAME]','[TITLE]', '[DESCRIPTION]', '[EXTERNAL_DOMAINS_LIST]']})
            self.model = BertForSequenceClassification.from_pretrained(
                'bert-base-uncased', 
                num_labels=2,
                problem_type="single_label_classification"
            )
            self.model.resize_token_embeddings(len(self.tokenizer))
        
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        
        self.max_length = 512
        self.batch_size = 32
        
    @classmethod
    def from_pretrained(cls, model_path):
        self = cls.__new__(cls)  # Bypass __init__
        
        # Carica tokenizer
        self.tokenizer = BertTokenizer.from_pretrained(model_path)
        
        # Carica modello fine-tuned
        self.model = BertForSequenceClassification.from_pretrained(model_path)
        
        # Setup
        self.model.resize_token_embeddings(len(self.tokenizer))
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        
        self.max_length = 512
        self.batch_size = 32
        
        return self
    
    def prepare_data(self, texts, labels):
        encodings = self.tokenizer(
            texts, 
            truncation=True, 
            padding=True, 
            max_length=self.max_length,
            return_tensors='pt'
        )
        
        dataset = TensorDataset(
            encodings['input_ids'],
            encodings['attention_mask'],
            torch.tensor(labels)
        )
        return dataset
    
    def train(self, train_texts, train_labels, epochs=2):  # Riduci epochs da 3 a 2
        dataset = self.prepare_data(train_texts, train_labels)
        train_loader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)
        
        # Usa optimizer con parametri ottimizzati
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=5e-5)
        
        self.model.train()
        for epoch in range(epochs):
            for batch in train_loader:
                optimizer.zero_grad()
                input_ids = batch[0].to(self.device)
                attention_mask = batch[1].to(self.device)
                labels = batch[2].to(self.device)
                
                outputs = self.model(
                    input_ids, 
                    attention_mask=attention_mask, 
                    labels=labels
                )
                
                loss = outputs.loss
                loss.backward()
                optimizer.step()
                
    def predict(self, texts):
        self.model.eval()
        results = {"predictions": [], "phishing_probability": []}
        dataset = self.prepare_data(texts, [0]*len(texts))  # dummy labels
        dataloader = DataLoader(dataset, batch_size=16)
            
        with torch.no_grad():
            for batch in dataloader:
                input_ids = batch[0].to(self.device)
                attention_mask = batch[1].to(self.device)
                
                # Ottieni le predizioni dal modello
                outputs = self.model(input_ids, attention_mask=attention_mask)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=1)
                
                # Predizione per ciascun esempio nel batch
                batch_predictions = torch.argmax(probabilities, dim=1).cpu().numpy()
                batch_phishing_probs = probabilities[:, 1].cpu().numpy()  # Probabilità per classe 1 (phishing)
                
                results["predictions"].extend(batch_predictions)
                results["phishing_probability"].extend(batch_phishing_probs)
                
        return results
    
    def predict_thresh(self, texts, threshold=0.5):
        """
        Restituisce le predizioni usando una soglia personalizzata per la probabilità di phishing.
        """
        self.model.eval()
        results = {"predictions": [], "phishing_probability": []}
        dataset = self.prepare_data(texts, [0]*len(texts))
        dataloader = DataLoader(dataset, batch_size=16)
        
        with torch.no_grad():
            for batch in dataloader:
                input_ids = batch[0].to(self.device)
                attention_mask = batch[1].to(self.device)

                outputs = self.model(input_ids, attention_mask=attention_mask)
                probs = torch.softmax(outputs.logits, dim=1)
                phishing_probs = probs[:, 1]  # probabilità classe 1

                batch_preds = (phishing_probs > threshold).long().cpu().numpy()
                results["predictions"].extend(batch_preds)
                results["phishing_probability"].extend(phishing_probs.cpu().numpy())

        return results