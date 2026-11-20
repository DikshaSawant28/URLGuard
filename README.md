# URLGuard – Phishing URL Risk Analyzer

A Python-based web application that analyzes URLs for common phishing indicators using a rule-based approach. It calculates a risk score and classifies URLs as Low, Medium, or High risk.

## Features

- Suspicious keyword detection
- IP address detection
- HTTPS verification
- Typosquatting detection
- Punycode detection
- Subdomain analysis
- Risk scoring and classification
- Explainable findings
- VirusTotal API integration
- Analysis history

## Tech Stack

Python | Streamlit | Requests | VirusTotal API

## How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/DikshaSawant28/URLGuard.git
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set your VirusTotal API key as an environment variable named `VIRUSTOTAL_API_KEY`.

4. Run the application:
   ```bash
   python -m streamlit run app.py
   ```

## Disclaimer

This project is developed for educational purposes. Its analysis results are indicative and do not guarantee website safety.
