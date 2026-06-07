import unittest
import os
import sys
import shutil

# Add parent directory to path so imports work correctly
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import init_db, add_user, get_user_by_username, verify_password, DB_PATH
from utils import extract_url_features, clean_url, analyze_email
from model import train_model, predict_phishing_probability, MODEL_PATH

class TestPhishShieldAI(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        # Initialize test databases and folders
        # Run init_db to seed tables
        init_db()
        
    def test_database_and_auth(self):
        # 1. Test database file exists
        self.assertTrue(os.path.exists(DB_PATH), "Database file should exist")
        
        # 2. Test user insertion and role hashing
        import uuid

        username = f"test_user_{uuid.uuid4().hex[:8]}"
        password = "Password123"
        user_id = add_user(username, password, "user")
        self.assertIsNotNone(user_id, "User registration should return an ID")
        
        # 3. Test verification
        user = get_user_by_username(username)
        self.assertIsNotNone(user, "User should be retrievable")
        self.assertEqual(user['role'], "user")
        
        # Test password validation
        self.assertTrue(verify_password(user['password_hash'], password), "Password verification should succeed")
        self.assertFalse(verify_password(user['password_hash'], "wrong_pass"), "Password verification should fail for wrong credentials")
        
    def test_url_feature_extraction(self):
        # Test clean URL helper
        self.assertEqual(clean_url("google.com"), "http://google.com")
        self.assertEqual(clean_url("https://amazon.com"), "https://amazon.com")
        
        # Test feature extraction on safe URL
        safe_url = "https://google.com"
        features, reasons = extract_url_features(safe_url)
        self.assertEqual(features['is_https'], 1)
        self.assertEqual(features['has_ip'], 0)
        self.assertEqual(features['similarity_to_popular_domains'], 0)
        self.assertEqual(len(reasons), 0, "Legitimate clean domain should have 0 triggers")
        
        # Test feature extraction on phishing URL
        phish_url = "http://paypal-security-login.com"
        features, reasons = extract_url_features(phish_url)
        self.assertEqual(features['is_https'], 0)
        self.assertTrue(features['suspicious_keyword_count'] > 0)
        self.assertEqual(features['similarity_to_popular_domains'], 1, "Impersonating PayPal should trigger similarity check")
        self.assertTrue(len(reasons) > 0, "Phishing domain should trigger reasons")
        
    def test_ml_model_train_and_predict(self):
        # Train model initially
        sample_count = train_model()
        self.assertTrue(sample_count > 0, "Model should train on at least some data")
        self.assertTrue(os.path.exists(MODEL_PATH), "Model file should be saved")
        
        # Check prediction probability
        prob, _, reasons = predict_phishing_probability("http://paypal-security-login.com")
        self.assertTrue(prob > 0.5, f"Phishing URL should have high probability (got {prob})")
        self.assertTrue(len(reasons) > 0, "Phishing prediction should include explainable reasons")
        
        # Check safe URL probability
        prob_safe, _, _ = predict_phishing_probability("https://google.com")
        self.assertTrue(prob_safe < 0.2, f"Safe URL should have low probability (got {prob_safe})")
        
    def test_email_analysis(self):
        phish_email = "URGENT: Your bank account is suspended immediately. Confirm billing details on verify-online.com."
        analysis = analyze_email(phish_email)
        self.assertTrue(analysis['risk_score'] > 50, "Phishing email should have a high risk score")
        self.assertEqual(analysis['classification'], "Phishing")
        self.assertTrue(len(analysis['reasons']) > 0)
        self.assertTrue(analysis['urgent_count'] > 0)

if __name__ == "__main__":
    unittest.main()
