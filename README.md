# YoroiPhish

## 🔍 Sistema avanzato di rilevamento phishing

### 🚀 Introduzione:

YoroiPhish è un sistema avanzato di rilevamento phishing che combina tecniche di machine learning, analisi strutturale, elaborazione del linguaggio naturale e visione artificiale per identificare siti web malevoli con elevata precisione.

**Obiettivi:**
- Sviluppare un sistema multi-livello per il rilevamento automatico di siti phishing
- Combinare analisi di URL, contenuto HTML e aspetto visivo per una valutazione completa
- Minimizzare i falsi positivi mantenendo un'elevata capacità di identificazione delle minacce
- Creare un sistema scalabile ed efficiente per la protezione in tempo reale

**Funzionamento:**
Il nostro approccio si basa su tre pilastri fondamentali:
1. **Analisi strutturale** - Estrazione di 98 caratteristiche dagli URL e dal codice HTML
2. **Analisi semantica** - Elaborazione del contenuto testuale con modelli BERT per rilevare anomalie linguistiche
3. **Analisi visiva** - Utilizzo di reti neurali convoluzionali per identificare elementi visivi tipici del phishing

Questi tre livelli di analisi vengono integrati attraverso un sistema di ensemble ottimizzato che bilancia i punteggi di ciascun modello per massimizzare precisione e recall.

**Utilizzo:**
YoroiPhish è progettato per funzionare sia come sistema di monitoraggio continuo che per analisi puntuali:
- Può essere integrato in soluzioni di sicurezza esistenti per la protezione di organizzazioni
- Consente l'analisi di URL sospetti in tempo reale
- Fornisce report dettagliati con spiegazione delle caratteristiche più significative
- Si puo' auto-aggiornare con nuovi pattern di phishing grazie all'apprendimento continuo

**Risultati:**
Le nostre valutazioni mostrano che l'approccio ensemble supera significativamente i singoli modelli, raggiungendo metriche di performance elevate anche su dataset complessi e siti di phishing sofisticati.

### ✅ 1️⃣ Raccolta dei Siti:
File: [clean_phishing](src/clean_phishing.py), [data_collection](src/data_collection.py), [screenshot_capture](src/screenshot_capture.py), [clean](src/clean.py)

**Siti legittimi**:
- Scaricamento da **[Tranco](https://tranco-list.eu/top-1m.csv.zip)** del **dataset** con il **milione** dei **siti più visitati**.
- **Estrazione** dei **primi 10.000 siti** per assicurarsi della loro **legittimità**.
- Per ogni sito selezionato casualmente, estrazione di **3 URL unici** tramite **CommonCrawl**, con **controllo degli errori** (es. 404) e **passaggio** al successivo se necessario.
- Implementazione di **delays** tra le **richieste** per rispettare le **policy** dei **server**.
- **Pulizia** degli **URL** per prevenire eventuali **problematiche** nel download degli **HTML**.
- Salvataggio degli **HTML** nella cartella [`raw/legit`](data/raw/legit) e creazione del **CSV** [legit_sites](data/results/legit_sites.csv) (in [`results`](data/results/)) contenente: **nome del dominio**, **URL** e **percorso** dell'**HTML**.

**Siti di phishing**:
- Download regolare dei **CSV** aggiornati da **[PhishStats](https://phishstats.info/)**.
- **Pulizia** dei dati con selezione dei **siti** aventi uno **Score** superiore a **5** (scala 1-10).
- **Estrazione** di informazioni quali **data**, **punteggio**, **URL** e **indirizzo IP** (data, punteggio e IP mantenuti per possibili utilizzi futuri).
- **Automatizzazione** del processo per **aggiornare** il **CSV esistente** con i nuovi dati.
- Salvataggio degli **HTML** nella cartella [`raw/phishing`](data/raw/phishing) e creazione di un **CSV** [phish_sites](data/results/phish_sites.csv) (in [`results`](data/results/)) con: **nome del dominio**, **URL** e **percorso** dell'**HTML**.

**Screenshot e Verifica Dati**:
- Cattura **parallela** degli **screenshot** di tutti i siti usando **[screenshot_capture](src/screenshot_capture.py)** con **multi-threading**.
- **Verifica dell'integrità** dei dati scaricati tramite **[clean](src/clean.py)** per garantire la coerenza tra i file HTML e i record nei CSV.
- **Ridimensionamento** degli screenshot per standardizzare le dimensioni per l'addestramento dei modelli visivi.

### ✅ 2️⃣ Feature Extraction 
File: [merge_results_csvs](src/merge_results_csvs.py), [feature_extraction](src/feature_extraction.py), [parsing](src/parsing.py), [train_csv_creation](src/train_csv_creation.py)

**1. Feature basate su URL** ([feature_extraction](src/feature_extraction.py)):
Estratte **55 feature** dagli URL, tra cui:
- **Statistiche di Base**: 
  - Lunghezza URL
  - Lunghezza hostname (`f1-f2`)
- **Caratteri Speciali**: 
  - Conteggio di punti, trattini
  - Presenza di @, ?, &, ecc. (`f4-f19`)
- **Termini Comuni**: 
  - Presenza di www, .com, http(s) (`f21-f25`)
- **Analisi Numerica**:
  - Rapporto cifre nell'URL
  - Rapporto cifre nell'hostname (`f26-f27`)
- **Analisi del Dominio**: 
  - Rilevamento Punycode (`f28`)
  - Presenza di porte (`f29`)
  - Analisi TLD (`f30-f31`)
  - Analisi sottodomini (`f32-f33`)
- **Indicatori di Sicurezza**:
  - URL basati su IP (`f3`)
  - TLD sospetti (`f55`)
  - Rilevamento abuso nomi brand (`f52-f54`)
  - Servizi di URL shortening (`f36`)
- **Analisi Lessicale**:
  - Statistiche parole in URL, hostname e percorso (`f40-f50`)
  - Rilevamento keyword di phishing (`f51`)

**2. Analisi del Contenuto HTML** ([parsing](src/feature_extraction.py)):
- **Analisi delle Risorse**:
  - Conteggio risorse *HTTPS/HTTP*
  - Rilevamento e conteggio *domini esterni*
  - Calcolo rapporti tra risorse
- **Analisi Struttura DOM**:
  - Profondità *DOM* e conteggio nodi
  - Rapporto foglie DOM
  - Rilevamento *form*
- **Elementi di Sicurezza**:
  - Presenza *sigilli SSL*
  - Rilevamento input *password*
  - Campi input *nascosti*
  - Conteggio *IFrame*
- **Analisi Contenuti**:
  - Rilevamento *lingua* e *incongruenze*
  - Struttura *heading* (conteggio h1, h2)
  - Analisi *link* e *immagini*
  - Elementi *JavaScript* (script inline ed esterni)
  - Rilevamento uso *cookie*
- **Indicatori di Brand e Affidabilità**:
  - Rilevamento *logo*
  - Presenza *copyright*
  - Analisi *favicon*

**3. Elaborazione Dati** ([merge_results_csvs](src/merge_results_csvs.py), [train_csv_creation](src/train_csv_creation.py)):
- Unione dataset legittimi e phishing ([sites](data/results/sites.csv))
- Combinazione delle feature (URL + HTML), normalizzazione e preprocessing ([train_csv_creation](src/train_csv_creation.py))
- Generazione dataset finale con etichette binarie (`phishing`/`legittimo`) ([features](trainingdata/features.csv))

### ✅ 3️⃣ Machine Learning
File: [ml_models](src/ml_models.py), [merge_text_data](src/merge_text_data.py), [clean_text_data](src/clean_text_data.py), [bert_model](src/bert_model.py), [cnn_model](src/cnn_model.py)

- **Modelli Strutturali** ([ml_models](src/ml_models.py)): 
  - Random Forest/XGBoost/LightGBM/CatBoost/Logistic Regression/Linear SVM/Multi-layer Perceptron
  - Addestramento su features numeriche estratte da HTML/URL 
  - Ottimizzazione tramite cross-validation e grid search

- **NLP** ([bert_model](src/bert_model.py), [merge_text_data](src/merge_text_data.py), [clean_text_data](src/clean_text_data.py)):
  - Preparazione del testo HTML con merge e pulizia dedicati
  - Fine-tuning di BERT per classificazione di phishing testuale
  - Analisi del contenuto semantico delle pagine web

- **Deep Learning** ([cnn_model](src/cnn_model.py)):
  - CNN specializzata per analisi degli screenshot
  - Identificazione di pattern visivi caratteristici del phishing
  - Riconoscimento di clonazioni di siti legittimi

Riguardo ai Modelli presi da HuggingFace credo che ottengano risultati così bassi perché addestrati su dataset con siti legittimi facilmente distinguibili da quelli di phishing, mentre il nostro dataset tende ad essere molto vario e complesso. Credo questo perché tendono entrambi a classificare anche molti siti legittimi come siti di phishing.  
Inoltre riguardo al primo, oltre all'HTML stesso, è stato addestrato anche su questi:  
  1. rec_id - record number  
  2. url - URL of the webpage  
  3. website - Filename of the webpage (i.e. 1635698138155948.html)  
  4. result - Indicates whether a given URL is phishing or not (0 for legitimate and 1 for phishing).  
  5. created_date - Webpage downloaded date  

e questo avrebbe potuto minare la capacità del modello di lavorare solo ed esclusivamente su file HTML (dargli l'url non avrebbe senso perché abbiamo già altri modelli per quello e la data abbiamo deciso in precedenza di non darla ai modelli per non rischiare che fossero eccessivamente influenzati da questa feature).

### ✅ 4️⃣ Sistema di Detection e Test Finali
- **Ensemble di modelli**:
  - Combinazione ottimizzata dei punteggi dai diversi classificatori
  - Sistema di voting pesato con threshold configurabile
  - Implementazione di regole di decisione personalizzate
  
- **Test e validazione**:
  - Valutazione su dataset Yoroi indipendente
  - Test real-time su URL forniti dall'utente
  - Generazione di report dettagliati con analisi delle feature critiche

### ✅ 5️⃣ Implementazione API
Per finire abbiamo implementato le API necessarie all'utilizzo di questo sistema. Aggiunt celery come task manager per permettere il lancio di più richieste in parallelo.

## 💡 Come Funziona nella Pratica?
1. **REPERIMENTO DEI SITI**
  - Scarichiamo a mano da **[Tranco](https://tranco-list.eu/top-1m.csv.zip)** un csv con il primo milione di siti più visitati negli ultimi 30 giorni e ci limitiamo a tenere i primi 10mila (csv in [data/external](data/external): **[top10k.csv](data/external/top10k.csv)**)

  - Una volta al giorno scarichiamo a mano da **[PhishStats](https://phishstats.info/)** un csv con i siti di phishing rilevati negli ultimi 30 giorni che viene aggiornato ogni 90 minuti.  
  Il csv viene scaricato in [external](data/external) e nella **cella 9** del [main](main.ipynb), richiamando le funzioni in **[clean_phishing.py](src/clean_phishing.py)**, i nuovi record vengono aggiunti al vecchio csv **[phish_score_cleaned.csv](data/external/phish_score_cleaned.csv)** che viene aggiornato e, una volta finito questo processo, il file appena scaricato viene rimosso.

  - I siti che utilizziamo per testare i risultati dei nostri modelli li prendiamo da un'altra fonte rispetto agli altri. Utilizziamo un csv preso da **HuggingFace** e scarichiamo anch'esso in [external](data/external):  **[test.csv](data/external/test.csv)**.

2. **ESTRAZIONE DEI DATI DAI SITI**
  - Nella **cella 7** del [main](main.ipynb) richiamando la funzione `download_legit_data` in **[data_collection.py](src/data_collection.py)**, per ogni esecuzione, scarichiamo casualmente gli **HTML** di 1000 dei **siti legittimi** indicati in **[top10k.csv](data/external/top10k.csv)** che finiscono in [raw/legit](data/raw/legit). Di ciascun sito scarichiamo gli HTML di 3 sue diverse pagine.  
  In [results](data/results) creiamo in tempo reale **[legit_sites.csv](data/results/legit_sites.csv)** con il *nome del dominio*, gli *url* e il *percorso del file HTML* appena salvato.  
  Facciamo attenzione a ricevere **output comprensivi** così da visualizzare immediatamente se l'HTML di un sito è stato scaricato correttamente, il numero di siti scaricati ed eventuali eccezioni o errori.  
  Inoltre ci assicuriamo subito che non provi a scaricare dati dai domini dei siti di cui abbiamo già gli HTML e che sono salvati in [legit_sites.csv](data/results/legit_sites.csv).

  - Nella **cella 10** del [main](main.ipynb) richiamando la funzione `download_phishing_data` in **[data_collection.py](src/data_collection.py)** scarichiamo gli **HTML** dei **siti di phishing** indicati in **[phish_score_cleaned.csv](data/external/phish_score_cleaned.csv)** che finiscono in [raw/phishing](data/raw/phishing).  
  In [results](data/results) ci salviamo **[phish_sites.csv](data/results/phish_sites.csv)** che è stato creato in tempo reale con il *nome del dominio*, gli *url* e il *percorso del file HTML* appena salvato.  
  Facciamo attenzione a ricevere **output comprensivi** così da visualizzare immediatamente se l'HTML è stato scaricato correttamente, se era già stato scaricato (di conseguenza facendo in modo che non lo riscarichi), se il sito risulta irraggiungibile o se il browser restituisce altri errori.  
  In caso un sito risulti irraggiungibile rimuoviamo il record corrispondente da [phish_score_cleaned.csv](data/external/phish_score_cleaned.csv) in modo che, se dovesse essere aggiornato il dataset, non consideri questi siti ( *generalmente i siti di phishing risultano irraggiungibili perché bloccati, di conseguenza provare una nuova volta a scaricare dati che li riguardano non avrebbe senso* ).

  - Nella **cella 15** del [main](main.ipynb) richiamando la funzione `batch_capture_screenshots_parallel` in **[screenshot_capture.py](src/screenshot_capture.py)** scarichiamo gli **screenshot** di tutti i siti presenti in **[sites.csv](data/results/sites.csv)** ( *bisognerà assicurarsi che questo file sia stato aggiornato con eventuali nuovi record prima di poter eseguire questa cella* ).  
  Gli screenshot vengono scaricati in **data/raw/screenshots /[legit](data/raw/screenshots/legit)** e **/[phishing](data/raw/screenshots/phishing)** mentre in [results](data\results) viene creato in tempo reale **[screenshot_results.csv](data\results\screenshot_results.csv)**.  
  Qui usiamo **8 threads** ( *potrebbe dover essere necessario modificarne il numero in base alle prestazioni del proprio computer - in caso modificare il parametro `max_workers` nella funzione `batch_capture_screenshots_parallel` in [screenshot_capture.py](src/screenshot_capture.py)* ) contemporaneamente per poter catturare il maggior numero di screenshot il più *velocemente* possibile, riprovando 2 volte in caso di errori nella cattura dello screenshot del dominio, incrementando ogni volta il tempo di attesa per assicurarsi che lo screenshot venga catturato *correttamente*.  
  Nel [main](main.ipynb), dopo aver stampato il numero di siti ancora da processare, **visualizziamo** in modo distinto se gli screenshot di ciascun dominio sono stati scaricati correttamente o se ci sono stati degli errori.

3. **PREPROCESSING DEI DATI SCARICATI**
  - Nelle **celle 12 e 13** del [main](main.ipynb), grazie anche alla funzione `verify_data_integrity` in **[clean.py](src\clean.py)**, ci assicuriamo che tutti gli HTML scaricati siano anche presenti in **[phish_sites.csv](data\results\phish_sites.csv)** e che se ci sono dei record nel csv di cui non abbiamo l'HTML vengano rimossi.

  - Nelle **celle 17 e 19** del [main](main.ipynb) *ripuliamo* gli **screenshot** e **[screenshot_results.csv](data\results\screenshot_results.csv)**, innanzitutto eliminando quelli di dimensioni troppo ridotte e, in seguito, *ridimensionandoli* tutti alla definizione media di tutti gli screenshot scaricati (per facilitare il successivo addestramento della CNN).  
  Poi controlliamo anche che tutti gli screenshot scaricati siano anche presenti in [screenshot_results.csv](data\results\screenshot_results.csv) e che se ci sono dei record nel csv di cui non abbiamo lo screenshot vengano rimossi.

4. **ESTRAZIONE DELLE FEATURE**
  - Nella **cella 21** del [main](main.ipynb) richiamiamo la funzione `process_directory` di **[parsing.py](src\parsing.py)**, iniziamo il parsing degli HTML estraendo le varie feature per creare **[html_phishing_numeric.csv](data\processed\html_phishing_numeric.csv)**, **[html_phishing_text.csv](data\processed\html_phishing_text.csv)**, **[html_legit_numeric.csv](data\processed\html_legit_numeric.csv)**, **[html_legit_text.csv](data\processed\html_legit_text.csv)** in [processed](data\processed).  
  I csv "**numerici**" verranno usati insieme a quelli con le feature degli url per addestrare *Random Forest*, *XGBoost*, *LightGBM*, *CatBoost*, *Logistic Regression*, *Linear SVM* e un *Multi-Layer Perceptron*.
  I csv "**testuali**" verranno usati per addestrare il modello *BERT*.

  - Nelle **celle 23 e 24** del [main](main.ipynb), tramite le funzioni `merge_and_save_sites` e `merge_and_save_html_features` in **[merge_results_csvs.py](src\merge_results_csvs.py)**, mergiamo i file [legit_sites.csv](data\results\legit_sites.csv) e [phish_sites.csv](data\results\phish_sites.csv) in **[sites.csv](data\results\sites.csv)** nella cartella [results](data\results) e tutti i file "numerici" creati in precedenza in **[html_features.csv](data\trainingdata\html_features.csv)** nella cartella [trainingdata](data\trainingdata).

  - Nella **cella 25** del [main](main.ipynb) richiamiamo le funzioni `create_features_dataframe` e `save_features` del file **[feature_extraction.py](src\feature_extraction.py)** per creare **[url_features.csv](data\trainingdata\url_features.csv)** da tutti i siti presenti in [sites.csv](data\results\sites.csv).

  - Nella **cella 27** del [main](main.ipynb) utilizzando la funzione `create_final_csv` del file **[train_scv_creation.py](src\train_csv_creation.py)** creiamo **[merged_features.csv](data\trainingdata\merged_features.csv)**.  
  Il file viene creato direttamente tramite l'utilizzo delle funzioni usate nelle celle precedenti e non dai file appena creati.

5. **ADDESTRAMENTO DEI MODELLI**

  - Dalla **cella 30 alla cella 50** del [main](main.ipynb) impieghiamo le varie funzioni presenti in **[ml_models.py](src\ml_models.py)** per addestrare i modelli (**Random Forest, XGBoost, LightGBM, CatBoost, Logistic Regression, Linear SVM, Multi-Layer Perceptron**) sulle **features** degli **URL** e su quelle **numeriche** degli **HTML**, predire e visualizzare i loro risultati sul **[test.csv](data\results\test.csv)** e infine salvarli nella cartella [models](models).

  - Dalla **cella 52 alla cella 64** del [main](main.ipynb), richiamando la funzione `merge_text_features` di **[merge_text_data.py](src\merge_text_data.py)** uniamo i file con le **features testuali** degli **HTML** ([html_phishing_text.csv](data\processed\html_phishing_text.csv) e [html_legit_text.csv](data\processed\html_legit_text.csv)), grazie a `clean_text_features` di **[clean_text_data.py](src\clean_text_data.py)** facciamo un leggero preprocessing di ciò che otteniamo e con il **`BertPhishingClassifier`** da **[bert_model.py](src\bert_model.py)**, addestriamo il nostro **modello BERT**.  
  Infine facciamo le predizioni su **[html_test_text_labeled.csv](data/trainingdata/html_test_text_labeled.csv)**, stampiamo risultati e statistiche finali e salviamo il modello nella cartella [bert](models\bert) all'interno di [models](models).
  Il file **[html_test_text_labeled.csv](data/trainingdata/html_test_text_labeled.csv)** in [trainingdata](data\trainingdata) che creiamo in seguito corrisponde ai dati finali su cui viene addestrato il BERT.

  - Dalla **cella 66 alla cella 71** del [main](main.ipynb) utilizziamo **[cnn_model.py](src\cnn_model.py)** per addestrare una **Rete Neurale Convoluzionale (CNN)** sugli **screenshot** delle pagine web catturati in precedenza. Il processo include:
    - Caricamento degli screenshot dalle cartelle **[legit](data/raw/screenshots/legit)** e **[phishing](data/raw/screenshots/phishing)** utilizzando **[screenshot_results.csv](data\results\screenshot_results.csv)**
    - Salvataggio delle **predizioni** nella cartella **["cnn" in "models"](models\cnn)**
    - Valutazione sugli screenshot dei siti presenti in **[test_screenshots.csv](data\results\test_screenshots.csv)** (salvati in [test_legit](data\raw\screenshots\test_legit) e [test_phishing](data\raw\screenshots\test_phishing)) e generazione di metriche (accuracy, precision, recall, F1-score)
    - Visualizzazione delle **performance** tramite curve ROC e confusion matrix
    - Salvataggio del modello addestrato come **[cnn_model.h5](models\cnn\cnn_model.h5)** nella cartella [cnn](models\cnn) all'interno di [models](models)

6. **AGGREGAZIONE DEI RISULTATI DEI DATI**
  Nelle **celle 73-81** del [main](main.ipynb), dedicate all'**Aggregazione dei Risultati** e al **Decision Engine**, implementiamo il sistema completo:

    1. **CARICAMENTO DEI MODELLI ADDESTRATI**  
      Utilizzo di **joblib** per caricare il modello **[random_forest.pkl](models/random_forest.pkl)** addestrato.  
      Caricamento del **modello BERT** dalla cartella **[bert](models/bert)**.  
      Importazione della **CNN** da **[cnn_model.h5](models/cnn/cnn_model.h5)**.  
      Importazione delle **reference hash ID** da **[test.csv](data/results/test.csv)** per il tracciamento coerente delle predizioni.

    2. **GENERAZIONE DELLE PROBABILITÀ PER MODELLO**  
      Estrazione delle **feature specifiche** per ciascun modello dai file **[test_features.csv](data/trainingdata/test_features.csv)** e **[hash_id&text_for_bert.csv](data/results/hash_id&text_for_bert.csv)** (quest'ultimo creato apposta per il funzionamento delll'Ensemble).  
      Creazione di un **DataFrame temporaneo** per ogni modello contenente le **probabilità di phishing**.

    3. **DECISION ENGINE CON REGOLE COMPOSITE**  
      Implementazione di **2 approcci di ensemble** (simple averaging, weighted averaging).  
      **Test sistematico delle combinazioni di pesi** per ciascun modello:
        - Valutazione di ogni combinazione tramite F1-score  
        
        Applicazione di **regole di decisione personalizzate**:
        - *Rule 1:* Se RF > 0.8 → phishing
        - *Rule 2:* Se CNN > 0.99 & RF > 0.5 → phishing
        - *Rule 3:* Se BERT > 0.99 & RF > 0.5 → phishing  
        
        **Ottimizzazione della soglia** per il massimo bilanciamento tra precisione e richiamo.  
        **Conclusione**: la combinazione di threshold 0.6 con le regole definite fornisce i **risultati migliori**.  
        Generazione delle **predizioni finali**.

    4. **ANALISI E VALUTAZIONE**  
      Creazione di **[model_predictions_comparison.csv](data/results/model_predictions_comparison.csv)** con tutte le probabilità e predizioni finali.  
      Calcolo di **metriche di performance** (accuracy, precision, recall, F1-score).  
      Visualizzazione della **confusion matrix** per l'ensemble finale.  
      Esportazione della configurazione del **modello di ensemble** finale in **[ensemble_model_config.json](models\ensemble\ensemble_model_config.json)**.

7. **TEST SUL DATASET YOROI**  
  Dalla **cella 83 alla 97** del [main](main.ipynb) abbiamo scaricato e preprocessato i dati relativi ai siti presenti nel **dataset Yoroi**, e infine abbiamo fatto le predizioni ottenendo un risultato che indica un *gran numero di siti di phishing* in confronto a quelli legittimi.

## 🤔 Come utilizzarlo?
1️⃣ Un nuovo URL sospetto viene scaricato e analizzato  
2️⃣ Ogni livello fornisce un punteggio di rischio  
3️⃣ Il sistema aggrega i risultati e decide se è phishing o no  
4️⃣ Se il sito è sospetto → alert.
