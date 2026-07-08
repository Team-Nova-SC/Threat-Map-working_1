# 🗺️ ThreatMap: Next-Gen Threat Intelligence Platform

![ThreatMap](https://img.shields.io/badge/Status-Active-success) ![License](https://img.shields.io/badge/License-MIT-blue) ![Version](https://img.shields.io/badge/Version-1.0.0-purple)

ThreatMap is a premium, full-stack Threat Intelligence platform designed to aggregate, analyze, and visualize Indicators of Compromise (IOCs) such as IPs, Domains, URLs, Hashes, and CVEs. 

It acts as a single pane of glass for security analysts to triage threats without manually querying dozens of different services. By combining deterministic data from industry-leading OSINT feeds with generative AI, ThreatMap automatically correlates infrastructure, attributes attacks to known Threat Actors, maps behaviors to the MITRE ATT&CK framework, and generates plain-English mitigation strategies.

---

## 🌟 Key Features

- **Unified IOC Scanning:** Scan IPs, Domains, URLs, Hashes, and CVEs in a single input.
- **Risk Scoring Engine:** Deterministic 0-100 risk score based on weighted aggregations from multiple feeds.
- **AI-Powered Mitigation:** Google Gemini 1.5 Pro generates actionable, plain-English mitigation briefs.
- **Premium UI/UX:** Built with Framer Motion, Tailwind CSS, and Next.js for a highly responsive, animated, and dark-mode optimized experience.
- **MITRE ATT&CK Mapping:** Automatically maps detected threat behaviors to specific MITRE TTPs.
- **Threat Actor Attribution:** Cross-references IOCs against a database of known APT groups.
- **Relationship Graph:** Visually plots connections between scanned subnets, ASNs, and malicious domains.
- **Watchlist & Community Notes:** Save critical threats and collaborate with team members.

---

## 🏗️ Architecture & Tech Stack

- **Frontend:** Next.js 14, React, Tailwind CSS, Framer Motion, Lucide Icons
- **Backend:** Python 3.12, FastAPI, Uvicorn, SQLAlchemy, Pydantic
- **Database:** PostgreSQL
- **Caching:** Redis (prevents rate-limiting on external OSINT APIs)
- **AI Integration:** Google Gemini (Vertex AI)

---

## 🔌 Integrated OSINT Feeds

ThreatMap integrates with the following security APIs. **You must provide your own API keys for these services.**

- [VirusTotal](https://www.virustotal.com/) (Primary conviction signal)
- [AbuseIPDB](https://www.abuseipdb.com/) (Crowdsourced abuse reports)
- [GreyNoise](https://www.greynoise.io/) (Noise & scanner filtering)
- [URLScan.io](https://urlscan.io/) (Visual DOM analysis & safe screenshots)
- [AlienVault OTX](https://otx.alienvault.com/) (Community threat pulses)
- [Shodan](https://www.shodan.io/) (Open ports & services)
- [IP-API](https://ip-api.com/) (Geolocation mapping - *No API key required*)

---

## 🚀 Installation & Local Setup

### Prerequisites
- Node.js (v18+)
- Python (v3.10+)
- PostgreSQL Server
- Redis Server

### 1. Database Setup
Create a PostgreSQL database named `threatmap` (or adjust the URL in your environment variables).

### 2. Backend Configuration
Navigate to the backend directory, set up your Python environment, and configure your API keys.

```bash
cd backend
python -m venv venv

# Windows
.\venv\Scripts\activate
# Mac/Linux
source venv/bin/activate

pip install -r requirements.txt
```

**Configure API Keys:**
Rename `.env.example` to `.env` and insert your private API keys. 
> **Note:** The `.env` file is included in `.gitignore` to prevent accidental credential leaks. Do not commit your real API keys!

```bash
# Example of what your .env should look like
DATABASE_URL=postgresql://postgres:password@localhost:5432/threatmap
REDIS_URL=redis://localhost:6379/0

VT_API_KEY=your_api_key_here
# ... add other keys
```

**Start the Backend:**
```bash
python -m uvicorn main:app --reload --port 8000
```

### 3. Frontend Configuration
Navigate to the frontend directory and start the Next.js development server.

```bash
cd frontend
npm install
npm run dev
```

The application will now be running at `http://localhost:3000`.

---

## 🛡️ License & Disclaimer

This project is open-source under the MIT License. 

*Disclaimer: ThreatMap is a tool for authorized security research and incident response. Ensure you comply with the Terms of Service of all integrated third-party APIs.*
