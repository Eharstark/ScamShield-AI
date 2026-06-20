# 🛡️ ScamShield AI

AI-Powered Scam Detection Platform built for ELEVATE 2026 Hackathon.

ScamShield AI helps users identify and analyze suspicious:

- 📩 SMS Messages
- 🔗 URLs & Phishing Links
- 📸 Screenshots (OCR-Based Analysis)

The platform uses a local explainable detection engine to detect scam indicators, calculate risk scores, and provide security recommendations.

---

## 🚀 Features

### SMS Analysis
- Detects urgency tactics
- Authority impersonation detection
- Credential theft indicators
- Financial scam patterns
- Risk score generation

### URL Analysis
- Suspicious domain detection
- URL shortening service detection
- Phishing indicators
- Scam keyword analysis
- Risk classification

### Screenshot Analysis
- OCR-powered text extraction
- Screenshot scam detection
- Risk assessment
- Security recommendations

---

## 🏗️ Architecture

Frontend

- HTML
- CSS
- JavaScript

Backend

- Python
- Flask
- Flask-CORS

Detection Engine

- Pattern Library
- URL Inspector
- OCR Processor
- Risk Scorer
- Explanation Engine

OCR

- Tesseract OCR
- PyTesseract
- Pillow

---

## 📂 Project Structure

```
ScamShield-AI/
│
├── backend/
│   ├── engine/
│   ├── routes/
│   ├── uploads/
│   ├── app.py
│   └── requirements.txt
│
├── frontend/
│   ├── css/
│   ├── js/
│   └── index.html
│
└── README.md
```

---

## ⚙️ Installation

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/ScamShield-AI.git
cd ScamShield-AI
```

### Backend Setup

```bash
cd backend

python -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt
```

### Install Tesseract OCR

Ubuntu / Kali

```bash
sudo apt update
sudo apt install tesseract-ocr
```

Verify installation

```bash
tesseract --version
```

---

## ▶️ Run Backend

```bash
cd backend

python app.py
```

Backend starts at:

```text
http://127.0.0.1:5000
```

Health Check:

```text
http://127.0.0.1:5000/api/health
```

---

## ▶️ Run Frontend

Using VS Code Live Server:

```text
http://127.0.0.1:5500/frontend/index.html
```

---

## 📊 Sample Analysis

### SMS

Input:

```text
URGENT! Your bank account will be blocked.
Click here immediately.
```

Output:

```text
Risk Score: 85+
Category: Credential Theft
Risk Level: High
```

---

## 🔒 Why ScamShield AI?

Unlike black-box AI systems, ScamShield AI provides:

- Transparent detection logic
- Explainable risk scoring
- Offline capability
- Fast analysis
- No paid APIs required

---

## 🎯 Hackathon Vision

Our goal is to protect users from:

- Banking scams
- UPI fraud
- Credential theft
- Phishing attacks
- Social engineering attacks

through an accessible AI-powered detection platform.

---

## 👨‍💻 Team

ELEVATE 2026 Hackathon Project

ScamShield AI Team

---

## 📜 License

MIT License