# 🛡️ Phishing Email Detector & Reporter

> **Prevents credential theft with high demo value. AI-powered email security analysis.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32-red.svg)](https://streamlit.io)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-orange.svg)](https://scikit-learn.org)

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Phishing Email Detector                          │
│                                                                      │
│  ┌──────────┐    ┌─────────────────────────────────────────────┐    │
│  │          │    │              Analysis Pipeline               │    │
│  │  app.py  │───▶│                                             │    │
│  │          │    │  ┌──────────┐  ┌──────────┐  ┌──────────┐  │    │
│  │Streamlit │    │  │ analyzer │  │  model   │  │ reporter │  │    │
│  │   GUI    │    │  │          │  │          │  │          │  │    │
│  │          │    │  │Rule-based│  │ TF-IDF + │  │PDF + HTML│  │    │
│  │3 Pages:  │    │  │URL scan  │  │ RandForst│  │ Reports  │  │    │
│  │• Analyze │    │  │LLM call  │  │ Predict  │  │          │  │    │
│  │• History │    │  └────┬─────┘  └────┬─────┘  └──────────┘  │    │
│  │• Settings│    │       │             │                        │    │
│  └──────────┘    │  ┌────▼─────────────▼─────┐                │    │
│                  │  │       Score Combiner     │                │    │
│                  │  │  ML×40% + Rule×35%       │                │    │
│                  │  │  + URL×25% = Risk Score  │                │    │
│                  │  └──────────────────────────┘                │    │
│                  └─────────────────────────────────────────────┘    │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                         utils.py                              │  │
│  │   Keyword dicts · URL helpers · Email parsing · History log   │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘

External APIs (all optional):
  VirusTotal API ─── URL reputation scanning
  Anthropic Claude ── Semantic phishing analysis  
  OpenAI GPT ──────── Alternative LLM analysis
```

## 📁 Project Structure

```
phishing-detector/
├── app.py            ← Main Streamlit web UI (3 pages)
├── analyzer.py       ← Rule-based + URL + LLM analysis engine
├── model.py          ← ML training (Random Forest + TF-IDF) & prediction
├── reporter.py       ← PDF & HTML report generation (ReportLab)
├── utils.py          ← Shared helpers, constants, history log
├── requirements.txt  ← Python dependencies
├── .env.example      ← API key template
├── README.md         ← This file
├── data/
│   ├── email_dataset.csv   ← Auto-generated synthetic training data
│   └── scan_history.json   ← Persistent scan history log
├── models/
│   ├── phishing_model.pkl       ← Trained Random Forest
│   └── tfidf_vectorizer.pkl     ← Fitted TF-IDF vectorizer
└── reports/
    └── *.pdf / *.html           ← Generated reports
```

---

## 🚀 Quick Start (5 minutes)

### 1. Prerequisites
- Python 3.10 or higher
- pip package manager

### 2. Clone / Download the Project
```bash
git clone <your-repo> phishing-detector
cd phishing-detector
```

### 3. Create Virtual Environment (recommended)
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Download NLTK Data (one-time)
```bash
python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"
```

### 6. Configure API Keys (optional)
```bash
cp .env.example .env
# Edit .env with your keys – all are optional
```

### 7. Run the App
```bash
streamlit run app.py
```

The app will open at **http://localhost:8501** 🎉

---

## 🎯 Features In Detail

### 🔍 Analysis Engine (analyzer.py)

| Check | Method | Description |
|-------|--------|-------------|
| Urgent language | Rule-based | 30+ urgency keyword patterns |
| Financial keywords | Rule-based | Banking, crypto, prize keywords |
| Credential requests | Rule-based | Password, login request patterns |
| Threat language | Rule-based | IRS, legal action, arrest threats |
| Sender spoofing | Rule-based | From vs Reply-To domain mismatch |
| Brand impersonation | Rule-based | Display name vs sender domain |
| HTML obfuscation | Rule-based | Hidden text, entity encoding |
| URL analysis | Rule+API | IP URLs, shorteners, entropy |
| Known phishing domains | Lookup | Internal blacklist |
| Lookalike domains | Pattern | paypa1.com, arnazon.com etc. |
| ML prediction | Random Forest | TF-IDF + 10 engineered features |
| Semantic analysis | LLM (optional) | Claude/GPT understanding |
| VirusTotal scan | API (optional) | URL reputation check |

### 📊 Risk Scoring

```
Final Score = (ML Score × 0.40) + (Rule Score × 0.35) + (URL Score × 0.25)

Thresholds:
  0–34%  → SAFE (green)
  35–69% → SUSPICIOUS (orange)
  70–100%→ PHISHING (red)
```

### 📄 Reports

- **PDF Report**: Professional multi-page report with metadata, score breakdown, 
  flag list, URL analysis table, keyword hits, recommendations, and email preview.
- **HTML Report**: Dark-themed self-contained HTML file, suitable for email or browser.
- **JSON Export**: Machine-readable full analysis data for integration.

---

## 🔑 API Keys (All Optional)

| Service | Purpose | Free Tier | Sign Up |
|---------|---------|-----------|---------|
| VirusTotal | URL reputation | 500 req/day | [virustotal.com](https://virustotal.com) |
| Anthropic Claude | LLM analysis | Pay-per-use | [console.anthropic.com](https://console.anthropic.com) |
| OpenAI | LLM analysis (alt) | Pay-per-use | [platform.openai.com](https://platform.openai.com) |

The app works fully without any API keys using local ML + rule-based analysis only.

---

## 📚 Training Data

By default, the model trains on **2,000 synthetic emails** generated at startup.

### Use Public Datasets for Better Accuracy

1. **SpamAssassin Corpus** (recommended):
   ```bash
   wget https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2
   ```

2. Format as CSV with columns: `subject`, `body`, `label` (0=legit, 1=phish)

3. Upload via Settings page → "Upload Custom Dataset"

4. Click "Train Model"

### Example CSV Format
```csv
subject,body,label
"URGENT: Verify your account","Click here immediately...",1
"Team meeting notes","Thanks for attending...",0
```

---

## 🧪 Testing the App

Try these sample emails (available in the UI):

1. **PayPal Phishing** – Classic account suspension scam with IP URL
2. **Prize Scam** – Nigerian lottery / inheritance pattern  
3. **Legitimate Work Email** – Normal team communication

---

## 🔧 Extending the Project

### Add a New Phishing Rule
In `analyzer.py`, add to the `rule_based_score()` function:
```python
# Example: detect base64 encoded attachments
if re.search(r'base64', body_lower):
    score += 8
    flags.append("Possible encoded attachment (base64)")
```

### Retrain with Real Data
```bash
python model.py  # trains with data/email_dataset.csv
```

### Connect to Gmail (IMAP Demo)
```python
import imaplib, email
mail = imaplib.IMAP4_SSL('imap.gmail.com')
mail.login('user@gmail.com', 'app_password')
mail.select('inbox')
# fetch latest email and pass to analyze_email()
```

---

## 🛡️ Security Notes

- This tool is for **educational and defensive purposes only**
- Never click links in emails flagged as phishing  
- If you already clicked a suspicious link, immediately change passwords
- Report actual phishing emails to: [reportphishing@apwg.org](mailto:reportphishing@apwg.org)

---

## 📄 License

MIT License – free for personal and commercial use.

---

*Built with ❤️ using Python, Streamlit, scikit-learn, and ReportLab*
