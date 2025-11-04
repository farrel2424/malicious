import streamlit as st
import pandas as pd
import numpy as np
import joblib
from urllib.parse import urlparse
import re
import requests
import time

# Page configuration
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="wide"
)

# Load models
@st.cache_resource
def load_models():
    try:
        model = joblib.load('../models/best_model.pkl')
        scaler = joblib.load('../models/scaler.pkl')
        label_encoder = joblib.load('../models/label_encoder.pkl')
        return model, scaler, label_encoder
    except Exception as e:
        st.error(f"Error loading models: {e}")
        return None, None, None

model, scaler, le = load_models()

# Feature extraction function (same as training)
def extract_features(url):
    """Extract features from URL"""
    features = {}
    
    try:
        parsed = urlparse(url)
        
        # Basic features
        features['url_length'] = len(url)
        features['domain_length'] = len(parsed.netloc)
        features['path_length'] = len(parsed.path)
        
        # Special characters
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_questionmarks'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_at'] = url.count('@')
        features['num_ampersand'] = url.count('&')
        features['num_exclamation'] = url.count('!')
        features['num_space'] = url.count(' ')
        features['num_tilde'] = url.count('~')
        features['num_comma'] = url.count(',')
        features['num_plus'] = url.count('+')
        features['num_asterisk'] = url.count('*')
        features['num_hashtag'] = url.count('#')
        features['num_dollar'] = url.count('$')
        features['num_percent'] = url.count('%')
        
        # URL components
        features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
        features['has_port'] = 1 if ':' in parsed.netloc and '@' not in parsed.netloc else 0
        features['is_https'] = 1 if parsed.scheme == 'https' else 0
        
        # Digits and letters
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_letters'] = sum(c.isalpha() for c in url)
        
        # Suspicious patterns
        features['has_suspicious_words'] = 1 if any(word in url.lower() for word in 
            ['login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm', 
             'banking', 'paypal', 'ebay', 'amazon']) else 0
        
        # Domain features
        domain_tokens = parsed.netloc.split('.')
        features['num_subdomains'] = len(domain_tokens) - 2 if len(domain_tokens) > 2 else 0
        
        # Query parameters
        features['num_params'] = len(parsed.query.split('&')) if parsed.query else 0
        
    except Exception as e:
        for key in ['url_length', 'domain_length', 'path_length', 'num_dots', 'num_hyphens',
                    'num_underscores', 'num_slashes', 'num_questionmarks', 'num_equals',
                    'num_at', 'num_ampersand', 'num_exclamation', 'num_space', 'num_tilde',
                    'num_comma', 'num_plus', 'num_asterisk', 'num_hashtag', 'num_dollar',
                    'num_percent', 'has_ip', 'has_port', 'is_https', 'num_digits',
                    'num_letters', 'has_suspicious_words', 'num_subdomains', 'num_params']:
            features[key] = 0
    
    return features

# Prediction function
def predict_url(url):
    """Predict if URL is malicious"""
    if model is None:
        return None, None, None
    
    try:
        # Extract features
        features = extract_features(url)
        features_df = pd.DataFrame([features])
        
        # Scale features
        features_scaled = scaler.transform(features_df)
        
        # Predict
        prediction = model.predict(features_scaled)[0]
        probabilities = model.predict_proba(features_scaled)[0]
        
        # Get label
        predicted_label = le.inverse_transform([prediction])[0]
        
        # Get probability for predicted class
        confidence = probabilities[prediction] * 100
        
        return predicted_label, confidence, probabilities
        
    except Exception as e:
        st.error(f"Prediction error: {e}")
        return None, None, None

# VirusTotal API function (BONUS)
def check_virustotal(url, api_key):
    """Check URL with VirusTotal API"""
    try:
        headers = {"x-apikey": api_key}
        
        # Submit URL for scanning
        scan_url = "https://www.virustotal.com/api/v3/urls"
        data = {"url": url}
        response = requests.post(scan_url, headers=headers, data=data)
        
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            
            # Get analysis results
            time.sleep(2)  # Wait for analysis
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers)
            
            if analysis_response.status_code == 200:
                results = analysis_response.json()['data']['attributes']['stats']
                return results
        return None
    except Exception as e:
        st.error(f"VirusTotal API Error: {e}")
        return None

# UI Layout
st.title("🛡️ Phishing URL Detector")
st.markdown("### Protect yourself from malicious websites using AI")

# Sidebar
with st.sidebar:
    st.header("About")
    st.info("""
    This tool uses Machine Learning to detect potentially malicious URLs including:
    - **Phishing** sites
    - **Malware** distribution
    - **Defacement** pages
    - **Benign** (safe) sites
    """)
    
    st.header("How it works")
    st.markdown("""
    1. Enter a URL
    2. AI analyzes 28+ features
    3. Get instant prediction
    4. (Optional) Cross-check with VirusTotal
    """)
    
    # VirusTotal API Key input
    st.header("🔐 VirusTotal Integration")
    vt_api_key = st.text_input("API Key (optional)", type="password", 
                                help="Get your free API key at virustotal.com")

# Main content
col1, col2 = st.columns([2, 1])

with col1:
    # URL input
    url_input = st.text_input("🔗 Enter URL to check:", 
                               placeholder="https://example.com",
                               help="Enter the full URL including http:// or https://")
    
    check_button = st.button("🔍 Analyze URL", type="primary", use_container_width=True)

with col2:
    st.metric("Model Loaded", "✅ Ready" if model else "❌ Error")

# Process URL
if check_button and url_input:
    if not url_input.startswith(('http://', 'https://')):
        st.warning("⚠️ Please include http:// or https:// in the URL")
    else:
        with st.spinner("Analyzing URL..."):
            # Get prediction
            result, confidence, probs = predict_url(url_input)
            
            if result:
                # Display results
                st.markdown("---")
                st.subheader("📊 Analysis Results")
                
                # Create columns for results
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Prediction", result.upper())
                
                with col2:
                    st.metric("Confidence", f"{confidence:.2f}%")
                
                with col3:
                    # Safety indicator
                    if result in ['benign']:
                        st.metric("Status", "✅ SAFE")
                    else:
                        st.metric("Status", "⚠️ SUSPICIOUS")
                
                # Show all probabilities
                st.subheader("Class Probabilities")
                prob_df = pd.DataFrame({
                    'Class': le.classes_,
                    'Probability': probs * 100
                }).sort_values('Probability', ascending=False)
                
                st.bar_chart(prob_df.set_index('Class'))
                
                # Show extracted features
                with st.expander("🔬 View Extracted Features"):
                    features = extract_features(url_input)
                    features_df = pd.DataFrame([features]).T
                    features_df.columns = ['Value']
                    st.dataframe(features_df, use_container_width=True)
                
                # VirusTotal check (if API key provided)
                if vt_api_key:
                    st.markdown("---")
                    st.subheader("🦠 VirusTotal Cross-Check")
                    with st.spinner("Checking with VirusTotal..."):
                        vt_results = check_virustotal(url_input, vt_api_key)
                        
                        if vt_results:
                            vt_col1, vt_col2, vt_col3, vt_col4 = st.columns(4)
                            
                            with vt_col1:
                                st.metric("Malicious", vt_results.get('malicious', 0))
                            with vt_col2:
                                st.metric("Suspicious", vt_results.get('suspicious', 0))
                            with vt_col3:
                                st.metric("Harmless", vt_results.get('harmless', 0))
                            with vt_col4:
                                st.metric("Undetected", vt_results.get('undetected', 0))
            else:
                st.error("Error making prediction. Please check the models.")

# Example URLs
st.markdown("---")
st.subheader("📝 Try these examples:")

example_urls = {
    "Benign": "https://www.google.com",
    "Suspicious": "http://signin-paypaI.com/verify-account",  # Note the capital I
    "Banking": "https://www.chase.com",
}

cols = st.columns(len(example_urls))
for idx, (label, url) in enumerate(example_urls.items()):
    with cols[idx]:
        if st.button(f"{label}\n{url}", use_container_width=True):
            st.rerun()

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center'>
    <p>Made with ❤️ using Streamlit | Model trained on phishing dataset</p>
    <p style='font-size: 12px;'>⚠️ This tool is for educational purposes. Always verify suspicious URLs through multiple sources.</p>
</div>
""", unsafe_allow_html=True)