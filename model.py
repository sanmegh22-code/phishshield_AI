import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from utils import extract_url_features, clean_url, SUSPICIOUS_KEYWORDS, POPULAR_DOMAINS
from database import get_dataset_items, get_db_connection

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishshield_rf.joblib")

FEATURE_NAMES = [
    'url_length',
    'dots_count',
    'hyphens_count',
    'subdomains_count',
    'is_https',
    'has_ip',
    'suspicious_keyword_count',
    'has_redirection',
    'similarity_to_popular_domains'
]

def generate_synthetic_data():
    """
    Generates a realistic set of legitimate and phishing URLs for model training.
    """
    legit_templates = [
        "https://{domain}.com",
        "https://www.{domain}.org",
        "https://{domain}.net/home",
        "https://{domain}.com/search?q=query",
        "https://{domain}.org/about/us.html",
        "https://sub.{domain}.com/dashboard"
    ]
    
    phish_templates = [
        "http://{brand}-security-login.com",
        "http://verify-{brand}-account-support.net",
        "https://{brand}-billing-update-alert.com/signin",
        "http://login.microsoft-{brand}-auth.net",
        "https://{brand}-id-reset-password.org/security",
        "http://secure-{brand}-online-banking.com/login",
        "http://accounts-{brand}-recovery.net/reset",
        "http://{brand}-verification-badge.com/login",
        "http://{typo}.com/login",
        "http://{ip}/login.php"
    ]
    
    brands = POPULAR_DOMAINS + ["bank", "chase", "paypal", "netflix", "wellsfargo", "gmail", "yahoo"]
    typos = ["paypa1", "g00gle", "amaz0n", "netf1ix", "faceb00k", "apple-id", "micros0ft"]
    ips = ["192.168.1.101", "203.0.113.5", "198.51.100.22", "98.139.180.149", "172.217.16.142"]
    
    legit_domains = [
        "google", "wikipedia", "github", "stackoverflow", "reddit", 
        "nytimes", "cnn", "bbc", "medium", "spotify", "dropbox", 
        "slack", "zoom", "trello", "jira", "bitbucket", "gitlab"
    ]
    
    urls = []
    labels = []
    
    # 1. Generate Legitimate URLs (Label = 0)
    for dom in legit_domains:
        for temp in legit_templates:
            urls.append(temp.format(domain=dom))
            labels.append(0)
            
    # Also add exact popular domains
    for b in brands:
        urls.append(f"https://{b}.com")
        labels.append(0)
        urls.append(f"https://www.{b}.com")
        labels.append(0)
        
    # 2. Generate Phishing URLs (Label = 1)
    for b in brands:
        for temp in phish_templates:
            # Skip templates requiring typo or ip
            if "{typo}" in temp or "{ip}" in temp:
                continue
            urls.append(temp.format(brand=b))
            labels.append(1)
            
    for t in typos:
        urls.append(f"http://{t}.com/signin")
        labels.append(1)
        urls.append(f"https://www.{t}-update.net/login")
        labels.append(1)
        
    for ip in ips:
        urls.append(f"http://{ip}/secure/banking")
        labels.append(1)
        urls.append(f"http://{ip}/login")
        labels.append(1)
        
    # Duplicate and add variations to reach ~1500+ items
    dataset = []
    for url, label in zip(urls, labels):
        dataset.append((url, label))
        
    return dataset

def train_model(custom_items=None):
    """
    Trains the Random Forest model on seed data, manual database entries, and synthetic data.
    """
    # Load database dataset items
    db_items = []
    try:
        db_items = [(item['url'], item['label']) for item in get_dataset_items()]
    except Exception:
        pass
        
    # Combine DB items, custom items, and synthetic data
    seed_data = db_items
    if custom_items:
        seed_data.extend(custom_items)
        
    # Always mix in synthetic data to have robust baseline features
    synth_data = generate_synthetic_data()
    all_data = seed_data + synth_data
    
    # Remove duplicates
    unique_data = {}
    for url, label in all_data:
        unique_data[clean_url(url)] = label
        
    # Extract features for all URLs
    features_list = []
    labels_list = []
    
    for url, label in unique_data.items():
        try:
            feats, _ = extract_url_features(url)
            features_list.append([feats[name] for name in FEATURE_NAMES])
            labels_list.append(label)
        except Exception:
            continue
            
    if not features_list:
        raise ValueError("No valid URL features extracted. Cannot train model.")
        
    # Create DataFrame
    X = pd.DataFrame(features_list, columns=FEATURE_NAMES)
    y = np.array(labels_list)
    
    # Train Random Forest Classifier
    clf = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
    clf.fit(X, y)
    
    # Save the model
    joblib.dump(clf, MODEL_PATH)
    print(f"Model trained successfully on {len(X)} samples and saved to {MODEL_PATH}")
    return len(X)

def predict_phishing_probability(url: str):
    """
    Predicts the probability that a URL is a phishing link.
    Returns:
        prob: float, probability of phishing (0.0 to 1.0)
        features: dict, extracted features
        reasons: list of strings, explainable AI list of reasons
    """
    # Ensure model is trained
    if not os.path.exists(MODEL_PATH):
        print("Model file not found. Initiating training...")
        train_model()
        
    # Load model
    clf = joblib.load(MODEL_PATH)
    
    # Extract features
    features, reasons = extract_url_features(url)
    
    # Prepare feature vector
    vector = [[features[name] for name in FEATURE_NAMES]]
    X = pd.DataFrame(vector, columns=FEATURE_NAMES)
    
    # Predict probability
    prob = float(clf.predict_proba(X)[0][1])
    
    # Adjust reasons list based on model prediction
    # If probability is high but reasons list is empty (unlikely but possible), add a generic warning
    if prob > 0.5 and not reasons:
        reasons.append("Heuristic behavior matches known phishing template patterns")
        
    return prob, features, reasons
