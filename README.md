# ThreatLens 🔍

**AI-Powered Phishing Detection Platform**

ThreatLens is a full-stack phishing detection system featuring a SwiftUI iOS app and a Python FastAPI backend powered by machine learning. Scan URLs and emails instantly to detect phishing threats with detailed risk analysis.

---

## ✨ Features

- 🔗 **URL Scanner** — Paste any URL to get an instant phishing risk score
- 📧 **Email Analyzer** — Analyze email content for phishing indicators
- 🧠 **ML-Powered** — XGBoost classifier trained on 30+ URL features
- 📊 **Risk Dashboard** — Visual breakdown of threat indicators
- 📱 **Native iOS App** — Beautiful SwiftUI interface with dark mode
- 🔐 **Secure Auth** — JWT-based authentication with password hashing

## 🏗️ Architecture

```
┌─────────────────────┐         ┌──────────────────────┐
│   iOS App (SwiftUI) │  ◄───►  │  Backend (FastAPI)    │
│                     │  HTTPS  │                       │
│  • URL Scanner      │         │  • ML Phishing Model  │
│  • Email Analyzer   │         │  • URL Feature Extract │
│  • Risk Dashboard   │         │  • WHOIS/SSL/DNS      │
│  • Scan History     │         │  • JWT Auth           │
└─────────────────────┘         └──────────────────────┘
```

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **iOS App** | SwiftUI, Swift 5.9 |
| **Backend** | Python 3.11, FastAPI |
| **ML Model** | XGBoost, scikit-learn |
| **Database** | SQLite (dev) / PostgreSQL (prod) |
| **Auth** | JWT (python-jose) |

## 🚀 Getting Started

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
uvicorn app.main:app --reload
```

API docs available at: `http://localhost:8000/docs`

### iOS App

Open `ios/ThreatLens.xcodeproj` in Xcode and run on a simulator or device.

## 📁 Project Structure

```
threatlens/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI entry point
│   │   ├── config.py            # Settings
│   │   ├── database.py          # DB setup
│   │   ├── models/              # ORM models & schemas
│   │   ├── routers/             # API routes
│   │   ├── services/            # Business logic
│   │   ├── ml/                  # ML model & training
│   │   └── utils/               # Helpers
│   ├── tests/                   # Unit tests
│   ├── requirements.txt
│   └── Dockerfile
├── ios/
│   └── ThreatLens/              # SwiftUI app
├── .gitignore
├── README.md
└── LICENSE
```

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 👤 Author

**Kanishk Sigar** — [@KanishkSigar](https://github.com/KanishkSigar)
