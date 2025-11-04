# Phishing URL Detector 🛡️

Machine Learning-based system to detect phishing and malicious URLs using AI.

## 🎯 Project Overview

This project trains multiple ML models to classify URLs into four categories:
- **Benign**: Safe, legitimate websites
- **Phishing**: Fake sites attempting to steal credentials
- **Malware**: Sites distributing malicious software
- **Defacement**: Compromised/vandalized websites

## 📊 Results

### Model Performance

| Model | Accuracy | Training Time |
|-------|----------|---------------|
| Random Forest | 96.5% | 12.3s |
| XGBoost | 97.2% | 8.7s |
| Logistic Regression | 92.1% | 2.1s |

**Best Model**: XGBoost (97.2% accuracy)

### Confusion Matrix



## 🚀 Quick Start

### Installation
```bash
# Clone repository
git clone https://github.com/farrel2424/phishing-detection-analysis.git
cd phishing-url-detector

# Install dependencies
pip install -r requirements.txt
```

### Running the Web App
```bash
cd app
streamlit run phish-detector.py
```

## 📁 Project Structure
```
phishing-url-detector/
├── data/
│   └── malicious_phish.csv          # Dataset
├── models/
│   ├── best_model.pkl                # Trained model
│   ├── scaler.pkl                    # Feature scaler
│   └── label_encoder.pkl             # Label encoder
├── notebooks/
│   └── phishing_detection_analysis.ipynb  # EDA & Training
├── app/
│   └── phish-detector.py             # Streamlit web app
├── requirements.txt                   # Dependencies
└── README.md                          # Documentation
```

## 🔬 Features Extracted

The model analyzes **28 features** from each URL:

- URL length metrics
- Special character counts
- Presence of IP addresses
- HTTPS usage
- Suspicious keywords
- Subdomain analysis
- Query parameters
- And more...

## 🦠 VirusTotal Integration (Bonus)

To enable VirusTotal cross-checking:

1. Get free API key from [VirusTotal](https://www.virustotal.com)
2. Enter API key in the sidebar
3. URLs will be checked against 70+ antivirus engines

## 📈 Model Training Details

### Dataset
- **Source**: Kaggle Phishing Website Detection Dataset
- **Size**: ~651,191 URLs
- **Split**: 80% training, 20% testing

### Feature Engineering
Extracted 28 meaningful features including URL structure, character patterns, and suspicious indicators.

### Models Tested
1. **Logistic Regression**: Fast baseline
2. **Random Forest**: Ensemble learning
3. **XGBoost**: Gradient boosting (best performance)

## 🛠️ Technologies Used

- **Python 3.8+**
- **scikit-learn**: ML models
- **XGBoost**: Gradient boosting
- **Streamlit**: Web application
- **pandas & numpy**: Data manipulation
- **matplotlib & seaborn**: Visualization

## 📝 Future Improvements

- [ ] Add LSTM model for sequence analysis
- [ ] Implement WHOIS lookup
- [ ] Add SSL certificate validation
- [ ] Create Chrome/Firefox extension
- [ ] Real-time URL monitoring
- [ ] Multi-language support

## 📄 License

MIT License

## 👤 Author

(https://github.com/farrel2424)

## 🙏 Acknowledgments

- Kaggle for the dataset
- VirusTotal for API access
- Streamlit for the amazing framework
