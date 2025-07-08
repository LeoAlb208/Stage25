import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, confusion_matrix
import xgboost as xgb
import lightgbm as lgb
from catboost import CatBoostClassifier
import joblib

def train_and_predict_random_forest(train_data_path, predict_data_path, target_column='is_phishing', random_state=42, n_estimators=100):
    """
    Train a Random Forest classifier on the entire training dataset and make predictions on a new dataset.
    
    Parameters:
    -----------
    train_data_path : str
        Path to the CSV file containing the training data
    predict_data_path : str
        Path to the CSV file containing the data to predict on
    target_column : str
        Name of the target column in the training dataset
    random_state : int
        Random seed for reproducibility
    n_estimators : int
        Number of trees in the random forest
        
    Returns:
    --------
    dict
        Dictionary containing model, predictions, and evaluation metrics
    """
    # Load the training data
    train_df = pd.read_csv(train_data_path)
    
    # Separate features and target from training data
    X_train = train_df.drop(target_column, axis=1)
    y_train = train_df[target_column]
    
    # Create and train the Random Forest model on the entire training dataset
    rf_model = RandomForestClassifier(n_estimators=n_estimators, random_state=random_state)
    rf_model.fit(X_train, y_train)
    
    # Load the prediction dataset
    predict_df = pd.read_csv(predict_data_path)
    
    # Check if target column exists in the prediction dataset
    has_target = target_column in predict_df.columns
    
    # Ensure prediction dataset has the same features as training data
    missing_cols = set(X_train.columns) - set(predict_df.columns)
    if missing_cols:
        raise ValueError(f"Prediction dataset is missing columns: {missing_cols}")
    
    # Separate features and target (if available) in prediction dataset
    if has_target:
        X_predict = predict_df.drop(target_column, axis=1)
        y_true = predict_df[target_column]
    else:
        X_predict = predict_df
    
    # Select only the columns used during training
    X_predict = X_predict[X_train.columns]
    
    # Make predictions
    y_pred = rf_model.predict(X_predict)
    
    # Calculate feature importance
    feature_importance = pd.DataFrame({
        'feature': X_train.columns,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    # Build result dictionary
    result = {
        'model': rf_model,
        'predictions': y_pred,
        'feature_importance': feature_importance
    }
    
    # Add evaluation metrics if target is available
    if has_target:
        result['y_true'] = y_true
        result['classification_report'] = classification_report(y_true, y_pred)
        result['confusion_matrix'] = confusion_matrix(y_true, y_pred)
    
    return result

def train_and_predict_xgboost(train_data_path, predict_data_path, target_column='is_phishing', random_state=42):
    """
    Train an XGBoost model on the entire training dataset and make predictions on a new dataset.
    """
    # Load training data
    train_df = pd.read_csv(train_data_path)
    X_train = train_df.drop(target_column, axis=1)
    y_train = train_df[target_column]
    
    # Create and train XGBoost model on the entire training dataset
    xgb_model = xgb.XGBClassifier(
        n_estimators=1000,
        learning_rate=0.01,
        max_depth=6,
        min_child_weight=3,
        gamma=0.1,
        subsample=0.9,
        colsample_bytree=0.7,
        colsample_bylevel=0.7,
        reg_alpha=0.01,
        reg_lambda=1.0,
        scale_pos_weight=1.0,  # calcola il giusto valore in base ai tuoi dati
        objective='binary:logistic',
        random_state=random_state,
        eval_metric='auc'  # considera AUC come metrica se stai lavorando con dati sbilanciati
    )
    
    xgb_model.fit(X_train, y_train)
    
    # Load prediction dataset
    predict_df = pd.read_csv(predict_data_path)
    
    # Check if target column exists in the prediction dataset
    has_target = target_column in predict_df.columns
    
    # Ensure prediction dataset has the same features as training data
    missing_cols = set(X_train.columns) - set(predict_df.columns)
    if missing_cols:
        raise ValueError(f"Prediction dataset is missing columns: {missing_cols}")
    
    # Separate features and target (if available) in prediction dataset
    if has_target:
        X_predict = predict_df.drop(target_column, axis=1)
        y_true = predict_df[target_column]
    else:
        X_predict = predict_df
    
    # Select only the columns used during training
    X_predict = X_predict[X_train.columns]
    
    # Make predictions
    y_pred = xgb_model.predict(X_predict)
    
    # Calculate feature importance
    feature_importance = pd.DataFrame({
        'feature': X_train.columns,
        'importance': xgb_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    # Build result dictionary
    result = {
        'model': xgb_model,
        'predictions': y_pred,
        'feature_importance': feature_importance
    }
    
    # Add evaluation metrics if target is available
    if has_target:
        result['y_true'] = y_true
        result['classification_report'] = classification_report(y_true, y_pred)
        result['confusion_matrix'] = confusion_matrix(y_true, y_pred)
    
    return result

def train_and_predict_lightgbm(train_data_path, predict_data_path, target_column='is_phishing', random_state=42):
    """
    Train a LightGBM model on the entire training dataset and make predictions on a new dataset.
    """
    # Load training data
    train_df = pd.read_csv(train_data_path)
    X_train = train_df.drop(target_column, axis=1)
    y_train = train_df[target_column]
    
    # Create and train LightGBM model on the entire training dataset
    lgb_model = lgb.LGBMClassifier(
        subsample= 1.0,
        reg_lambda= 1.0,
        reg_alpha= 0.1,
        colsample_bytree= 0.6,
        n_estimators=500,
        learning_rate=0.2,
        max_depth=9,
        num_leaves=15,
        min_child_samples=20,
        random_state=random_state
    )
    
    lgb_model.fit(X_train, y_train)
    
    # Load prediction dataset
    predict_df = pd.read_csv(predict_data_path)
    
    # Check if target column exists in the prediction dataset
    has_target = target_column in predict_df.columns
    
    # Ensure prediction dataset has the same features as training data
    missing_cols = set(X_train.columns) - set(predict_df.columns)
    if missing_cols:
        raise ValueError(f"Prediction dataset is missing columns: {missing_cols}")
    
    # Separate features and target (if available) in prediction dataset
    if has_target:
        X_predict = predict_df.drop(target_column, axis=1)
        y_true = predict_df[target_column]
    else:
        X_predict = predict_df
    
    # Select only the columns used during training
    X_predict = X_predict[X_train.columns]
    
    # Make predictions
    y_pred = lgb_model.predict(X_predict)
    
    # Calculate feature importance
    feature_importance = pd.DataFrame({
        'feature': X_train.columns,
        'importance': lgb_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    # Build result dictionary
    result = {
        'model': lgb_model,
        'predictions': y_pred,
        'feature_importance': feature_importance
    }
    
    # Add evaluation metrics if target is available
    if has_target:
        result['y_true'] = y_true
        result['classification_report'] = classification_report(y_true, y_pred)
        result['confusion_matrix'] = confusion_matrix(y_true, y_pred)
    
    return result

def train_and_predict_catboost(train_data_path, predict_data_path, target_column='is_phishing', random_state=42):
    """
    Train a CatBoost model on the entire training dataset and make predictions on a new dataset.
    """
    # Load training data
    train_df = pd.read_csv(train_data_path)
    X_train = train_df.drop(target_column, axis=1)
    y_train = train_df[target_column]
    
    # Creare un set di valutazione dividendo i dati di addestramento
    X_train_main, X_eval, y_train_main, y_eval = train_test_split(
        X_train, y_train, test_size=0.2, random_state=random_state
    )
    
    # Create and train CatBoost model
    cat_model = CatBoostClassifier(
        iterations=1000,
        learning_rate=0.01,
        depth=8,
        l2_leaf_reg=3,
        random_seed=random_state,
        verbose=False,
        early_stopping_rounds=30,
        use_best_model=True,
        bootstrap_type='Bernoulli',
        subsample=0.85,
        colsample_bylevel=0.8,
        auto_class_weights='Balanced'
    )
    
    # Passa l'eval_set a fit()
    cat_model.fit(
        X_train_main, 
        y_train_main,
        eval_set=[(X_eval, y_eval)],
        verbose=False
    )
    
    # Load prediction dataset
    predict_df = pd.read_csv(predict_data_path)
    
    # Check if target column exists in the prediction dataset
    has_target = target_column in predict_df.columns
    
    # Ensure prediction dataset has the same features as training data
    missing_cols = set(X_train.columns) - set(predict_df.columns)
    if missing_cols:
        raise ValueError(f"Prediction dataset is missing columns: {missing_cols}")
    
    # Separate features and target (if available) in prediction dataset
    if has_target:
        X_predict = predict_df.drop(target_column, axis=1)
        y_true = predict_df[target_column]
    else:
        X_predict = predict_df
    
    # Select only the columns used during training
    X_predict = X_predict[X_train.columns]
    
    # Make predictions
    y_pred = cat_model.predict(X_predict)
    
    # Calculate feature importance
    feature_importance = pd.DataFrame({
        'feature': X_train.columns,
        'importance': cat_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    # Build result dictionary
    result = {
        'model': cat_model,
        'predictions': y_pred,
        'feature_importance': feature_importance
    }
    
    # Add evaluation metrics if target is available
    if has_target:
        result['y_true'] = y_true
        result['classification_report'] = classification_report(y_true, y_pred)
        result['confusion_matrix'] = confusion_matrix(y_true, y_pred)
    
    return result

def train_and_predict_logistic_regression(train_data_path, predict_data_path, target_column='is_phishing', random_state=42):
    """
    Train a Logistic Regression model on the entire training dataset and make predictions on a new dataset.
    """
    # Load training data
    train_df = pd.read_csv(train_data_path)
    X_train = train_df.drop(target_column, axis=1)
    y_train = train_df[target_column]
    
    # Create and train Logistic Regression model on the entire training dataset
    lr_model = LogisticRegression(
        C=1.0,
        max_iter=1000,
        random_state=random_state
    )
    
    lr_model.fit(X_train, y_train)
    
    # Load prediction dataset
    predict_df = pd.read_csv(predict_data_path)
    
    # Check if target column exists in the prediction dataset
    has_target = target_column in predict_df.columns
    
    # Ensure prediction dataset has the same features as training data
    missing_cols = set(X_train.columns) - set(predict_df.columns)
    if missing_cols:
        raise ValueError(f"Prediction dataset is missing columns: {missing_cols}")
    
    # Separate features and target (if available) in prediction dataset
    if has_target:
        X_predict = predict_df.drop(target_column, axis=1)
        y_true = predict_df[target_column]
    else:
        X_predict = predict_df
    
    # Select only the columns used during training
    X_predict = X_predict[X_train.columns]
    
    # Make predictions
    y_pred = lr_model.predict(X_predict)
    
    # Calculate feature importance (coefficients)
    feature_importance = pd.DataFrame({
        'feature': X_train.columns,
        'importance': np.abs(lr_model.coef_[0])  # Use absolute values for importance
    }).sort_values('importance', ascending=False)
    
    # Build result dictionary
    result = {
        'model': lr_model,
        'predictions': y_pred,
        'feature_importance': feature_importance
    }
    
    # Add evaluation metrics if target is available
    if has_target:
        result['y_true'] = y_true
        result['classification_report'] = classification_report(y_true, y_pred)
        result['confusion_matrix'] = confusion_matrix(y_true, y_pred)
    
    return result

def train_and_predict_linear_svm(train_data_path, predict_data_path, target_column='is_phishing', random_state=42):
    """
    Train a Linear SVM model on the entire training dataset and make predictions on a new dataset.
    """
    # Load training data
    train_df = pd.read_csv(train_data_path)
    X_train = train_df.drop(target_column, axis=1)
    y_train = train_df[target_column]
    
    # Create and train Linear SVM model on the entire training dataset
    svm_model = LinearSVC(
        C=1.0,
        max_iter=2000,  # More iterations for convergence
        random_state=random_state
    )
    
    svm_model.fit(X_train, y_train)
    
    # Load prediction dataset
    predict_df = pd.read_csv(predict_data_path)
    
    # Check if target column exists in the prediction dataset
    has_target = target_column in predict_df.columns
    
    # Ensure prediction dataset has the same features as training data
    missing_cols = set(X_train.columns) - set(predict_df.columns)
    if missing_cols:
        raise ValueError(f"Prediction dataset is missing columns: {missing_cols}")
    
    # Separate features and target (if available) in prediction dataset
    if has_target:
        X_predict = predict_df.drop(target_column, axis=1)
        y_true = predict_df[target_column]
    else:
        X_predict = predict_df
    
    # Select only the columns used during training
    X_predict = X_predict[X_train.columns]
    
    # Make predictions
    y_pred = svm_model.predict(X_predict)
    
    # Calculate feature importance (coefficients)
    feature_importance = pd.DataFrame({
        'feature': X_train.columns,
        'importance': np.abs(svm_model.coef_[0])  # Use absolute values for importance
    }).sort_values('importance', ascending=False)
    
    # Build result dictionary
    result = {
        'model': svm_model,
        'predictions': y_pred,
        'feature_importance': feature_importance
    }
    
    # Add evaluation metrics if target is available
    if has_target:
        result['y_true'] = y_true
        result['classification_report'] = classification_report(y_true, y_pred)
        result['confusion_matrix'] = confusion_matrix(y_true, y_pred)
    
    return result

def train_and_predict_mlp(train_data_path, predict_data_path, target_column='is_phishing', random_state=42):
    """
    Train a Multi-Layer Perceptron model on the entire training dataset and make predictions on a new dataset.
    """
    # Load training data
    train_df = pd.read_csv(train_data_path)
    X_train = train_df.drop(target_column, axis=1)
    y_train = train_df[target_column]
    
    # Create and train MLP model on the entire training dataset
    mlp_model = MLPClassifier(
        hidden_layer_sizes=(256, 128, 64),  # 3 hidden layers with decreasing sizes
        activation='tanh',
        solver='adam',
        alpha=0.0001,  # L2 regularization parameter
        batch_size='auto',
        learning_rate='adaptive',
        learning_rate_init=0.001,
        max_iter=1000,
        early_stopping=False,  # No early stopping when training on full dataset
        random_state=random_state
    )
    
    mlp_model.fit(X_train, y_train)
    
    # Load prediction dataset
    predict_df = pd.read_csv(predict_data_path)
    
    # Check if target column exists in the prediction dataset
    has_target = target_column in predict_df.columns
    
    # Ensure prediction dataset has the same features as training data
    missing_cols = set(X_train.columns) - set(predict_df.columns)
    if missing_cols:
        raise ValueError(f"Prediction dataset is missing columns: {missing_cols}")
    
    # Separate features and target (if available) in prediction dataset
    if has_target:
        X_predict = predict_df.drop(target_column, axis=1)
        y_true = predict_df[target_column]
    else:
        X_predict = predict_df
    
    # Select only the columns used during training
    X_predict = X_predict[X_train.columns]
    
    # Make predictions
    y_pred = mlp_model.predict(X_predict)
    
    # For MLP, we can look at the magnitude of the weights connecting
    # the input layer to the first hidden layer as a rough measure of feature importance
    # Calculate the absolute sum of weights for each feature
    feature_importances = np.abs(mlp_model.coefs_[0]).sum(axis=1)
    
    # Create feature importance dataframe
    feature_importance = pd.DataFrame({
        'feature': X_train.columns,
        'importance': feature_importances
    }).sort_values('importance', ascending=False)
    
    # Build result dictionary
    result = {
        'model': mlp_model,
        'predictions': y_pred,
        'feature_importance': feature_importance
    }
    
    # Add evaluation metrics if target is available
    if has_target:
        result['y_true'] = y_true
        result['classification_report'] = classification_report(y_true, y_pred)
        result['confusion_matrix'] = confusion_matrix(y_true, y_pred)
    
    return result

def save_model(model, file_path):
    """
    Save a trained model to disk using joblib.
    
    Parameters:
    -----------
    model : object
        The trained model to save
    file_path : str
        Path where the model will be saved
    """
    joblib.dump(model, file_path)
    
def load_model(file_path):
    """
    Load a trained model from disk using joblib.
    
    Parameters:
    -----------
    file_path : str
        Path where the model is saved
        
    Returns:
    --------
    object
        The loaded model
    """
    return joblib.load(file_path)