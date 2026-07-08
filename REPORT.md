# ThreatMap: Complete Project Report

## 1. PROJECT OVERVIEW

**What is ThreatMap**
ThreatMap is a premium, full-stack Threat Intelligence platform designed to aggregate, analyze, and visualize Indicators of Compromise (IOCs) such as IPs, Domains, URLs, Hashes, and CVEs. It acts as a single pane of glass for security analysts to triage threats without manually querying dozens of different services.

**Purpose and Goals**
The primary goal of ThreatMap is to accelerate incident response and threat hunting. By combining deterministic data from industry-leading OSINT feeds with generative AI, ThreatMap automatically correlates infrastructure, attributes attacks to known Threat Actors, maps behaviors to the MITRE ATT&CK framework, and generates plain-English mitigation strategies.

**Who it is for**
- **Security Operations Center (SOC) Analysts:** For rapid IOC triage and alert validation.
- **Threat Hunters:** To uncover correlated infrastructure and track adversary campaigns.
- **Incident Responders:** To generate immediate containment strategies using AI.
- **Security Engineers:** To manage watchlists and track organizational threat exposure.

**Version and Date**
- **Version:** 1.0.0 (Release Candidate)
- **Date:** June 2026

---

## 2. SYSTEM ARCHITECTURE

**Tech Stack**
- **Frontend:** Next.js 14, React, Tailwind CSS, Framer Motion, Lucide Icons, React Query.
- **Backend:** Python 3.12, FastAPI, Uvicorn, SQLAlchemy (ORM), Pydantic.
- **Database:** PostgreSQL (Primary Data Store).
- **Caching:** Redis (In-memory caching for external API responses to prevent rate limiting).
- **AI/ML:** Google Gemini 1.5 Pro (via Vertex AI / Google AI Studio).

**Frontend → Backend → APIs Flow Diagram**
```mermaid
graph TD
    A[Client UI / Next.js] -->|REST API Calls| B[FastAPI Backend]
    B -->|Check Cache| C[(Redis Cache)]
    C -- Miss --> B
    B -->|Async HTTP Requests| D[External OSINT APIs]
    D -->|JSON Data| B
    B -->|Process & Aggregate| B
    B -->|AI Prompt| E[Google Gemini]
    E -->|Mitigation Brief| B
    B -->|Read/Write| F[(PostgreSQL)]
    B -->|Return JSON| A
```

**Database Design**
The database is built on PostgreSQL using SQLAlchemy. It features tables for scanning history, watchlist management, threat actor profiles, community notes, and cached correlations. The design ensures that historical scans are immutable and that relationships (like many-to-many actor attributions) are properly indexed.

**Caching Layer**
Redis is implemented as an essential middleware. Every external API call (VirusTotal, AbuseIPDB, etc.) is wrapped in a caching function with a default TTL (Time To Live) of 24 hours. This drastically reduces API quota consumption and drops response times for known IOCs from ~5 seconds to < 50 milliseconds.

**Deployment Setup**
- **Frontend:** Node.js environment (can be hosted on Vercel or local Node server).
- **Backend:** Python virtual environment running Uvicorn workers.
- **Data Layer:** Local or managed instances of PostgreSQL and Redis.

---

## 3. ALL 26 FEATURES — FULL DETAILS

1. **Single IOC Scanning**
   - **What it does:** Scans individual IPs, URLs, Domains, or Hashes.
   - **How it works:** Routes request to specific handlers based on regex typing.
   - **APIs:** VirusTotal, AbuseIPDB, GreyNoise.
   - **Expected Output:** Aggregated JSON with a standardized 0-100 risk score.

2. **Bulk IOC Scanning**
   - **What it does:** Scans up to 50 IOCs simultaneously.
   - **How it works:** Uses `asyncio.gather` on the backend to process items concurrently.
   - **APIs:** Same as Single Scan.
   - **Expected Output:** Array of simplified risk assessments.

3. **Risk Scoring Engine**
   - **What it does:** Calculates a deterministic 0-100 threat score.
   - **How it works:** Applies weighted math to different feed responses (e.g., VT is weighted heavily, GreyNoise reduces score if "noise").
   - **APIs:** Internal logic.

4. **AI Mitigation Generation**
   - **What it does:** Writes a plain-English summary and remediation steps.
   - **How it works:** Feeds raw OSINT JSON into Google Gemini with a strict system prompt.
   - **APIs:** Google Gemini API.

5. **VirusTotal Integration**
   - **What it does:** Checks file/URL/IP reputation across 70+ antiviruses.
   - **How it works:** Hits VT v3 REST API.
   - **APIs:** VirusTotal.

6. **AbuseIPDB Integration**
   - **What it does:** Checks crowd-sourced IP abuse reports.
   - **How it works:** Hits the `check` endpoint for confidence scores.
   - **APIs:** AbuseIPDB.

7. **GreyNoise Noise Filtering**
   - **What it does:** Identifies benign internet scanners (e.g., Shodan, Googlebot).
   - **How it works:** Checks the RIOT (Rule It Out) dataset.
   - **APIs:** GreyNoise.

8. **URLScan.io Visual Analysis**
   - **What it does:** Grabs a screenshot of malicious URLs safely.
   - **How it works:** Submits a scan task, waits, and fetches the UUID result.
   - **APIs:** URLScan.io.

9. **AlienVault OTX Pulses**
   - **What it does:** Checks for community threat intelligence pulses.
   - **How it works:** Queries the OTX indicator endpoint.
   - **APIs:** AlienVault OTX.

10. **Threat Actor Correlation**
    - **What it does:** Links IP/Domains to known APTs (Advanced Persistent Threats).
    - **How it works:** Cross-references results with a local database of APT infrastructure and AI validation.
    - **APIs:** Internal Database + Gemini.

11. **MITRE ATT&CK Mapping**
    - **What it does:** Highlights the TTPs (Tactics, Techniques, Procedures) used.
    - **How it works:** Uses Gemini to map observed behaviors to the MITRE matrix.
    - **APIs:** Gemini.

12. **IP Geolocation Mapping**
    - **What it does:** Plots the physical location of an IP.
    - **How it works:** Leaflet.js renders coordinates fetched from IP-API.
    - **APIs:** IP-API.

13. **Relationship Graph Visualization**
    - **What it does:** Draws a node-edge graph of connected infrastructure.
    - **How it works:** Uses `react-graph-vis` to map subnets and ASNs.
    - **APIs:** Frontend internal logic.

14. **CVE Vulnerability Lookup**
    - **What it does:** Explains a specific CVE identifier.
    - **How it works:** Queries NIST NVD or CIRCL for CVE details.
    - **APIs:** NIST NVD.

15. **Shodan Host Analysis**
    - **What it does:** Identifies open ports and running services.
    - **How it works:** Queries the Shodan Host API.
    - **APIs:** Shodan.

16. **Watchlist Management**
    - **What it does:** Saves IOCs for future monitoring.
    - **How it works:** Stores indicator and notes in the `watchlists` PostgreSQL table.
    - **APIs:** Internal DB.

17. **Community Notes**
    - **What it does:** Allows analysts to leave comments on an IOC.
    - **How it works:** CRUD operations on the `notes` table linked to an indicator string.
    - **APIs:** Internal DB.

18. **PDF Report Export**
    - **What it does:** Generates a downloadable PDF of the threat analysis.
    - **How it works:** Uses `ReportLab` in Python to compile the data into a PDF buffer.
    - **APIs:** Internal Python library.

19. **Real-time Animated UI**
    - **What it does:** Provides a highly polished, responsive interface.
    - **How it works:** Framer Motion handles spring-based physics and transitions.
    - **APIs:** Framer Motion (Frontend).

20. **Premium Dashboard Analytics**
    - **What it does:** Shows global stats (Total Scans, Critical Threats, etc.).
    - **How it works:** Aggregates data from the `scans` table.
    - **APIs:** Internal DB.

21. **Redis Response Caching**
    - **What it does:** Prevents duplicate API calls within 24 hours.
    - **How it works:** Hashes the URL/Indicator and stores the raw JSON in Redis.
    - **APIs:** Redis.

22. **Asynchronous API Processing**
    - **What it does:** Ensures the server doesn't block while waiting for APIs.
    - **How it works:** Uses FastAPI `async def` and `aiohttp` for non-blocking I/O.
    - **APIs:** aiohttp.

23. **PostgreSQL Database Persistence**
    - **What it does:** Safely stores long-term state.
    - **How it works:** SQLAlchemy manages connections and schema migrations.
    - **APIs:** psycopg2.

24. **Automatic Retry & Rate Limit Handling**
    - **What it does:** Prevents crashes when free-tier APIs reject requests.
    - **How it works:** Implements exponential backoff and try-except blocks.
    - **APIs:** Python logic.

25. **Security & Availability Status Monitoring**
    - **What it does:** Warns the user if an API key is missing.
    - **How it works:** Environment variable validation on startup.
    - **APIs:** Internal logic.

26. **SpiderFoot OSINT Automation (Experimental)**
    - **What it does:** Automates deep-dive OSINT gathering.
    - **How it works:** Connects to a local SpiderFoot instance via its REST API.
    - **APIs:** SpiderFoot Local API.

---

## 4. ALL DATA SOURCES & APIs

| Service | Data Provided | Free Tier Limits | How ThreatMap Uses It | Endpoint |
|---------|--------------|------------------|-----------------------|----------|
| **VirusTotal** | Malware hashes, AV verdicts | 4 req/min, 500/day | Primary malicious conviction signal | `/api/v3/ip_addresses/{ip}` |
| **AbuseIPDB** | Crowd-sourced abuse reports | 1000 req/day | Validates active attacks (brute force) | `/api/v2/check` |
| **GreyNoise** | Benign scanner identification | API Key dependent | Reduces false positives for known scanners | `/v3/community/{ip}` |
| **URLScan.io** | DOM analysis, Screenshots | 5000 scans/day | Safe visual inspection of phishing sites | `/api/v1/scan/` |
| **AlienVault OTX**| Threat pulses, associated IOCs | Generous/Free | Finding related domains and hashes | `/api/v1/indicators/IPv4/{ip}/general` |
| **Shodan** | Open ports, vulnerabilities | 100 req/month (Dev) | Identifying exposed services | `/shodan/host/{ip}` |
| **IP-API** | Lat/Long, ISP, ASN | 45 req/min | Populating the Leaflet map | `/json/{ip}` |
| **Google Gemini** | NLP Analysis | 15 RPM, 1M TPM | Translating raw JSON into human briefs | `gemini-1.5-pro` |

---

## 5. DATABASE SCHEMA

**Table: scans**
- `id` (String, PK): UUID for the scan.
- `indicator` (String, Indexed): The IOC itself (e.g., '1.1.1.1').
- `type` (String): 'ip', 'domain', 'url', 'hash'.
- `risk_score` (Integer): The computed 0-100 score.
- `raw_data` (JSON): The full aggregated JSON from all APIs.
- `created_at` (DateTime): Timestamp.

**Table: watchlists**
- `id` (String, PK): UUID.
- `indicator` (String, Indexed): The IOC being watched.
- `type` (String): Type of IOC.
- `notes` (String): Analyst notes.
- `last_risk_score` (Integer): Cached score for dashboard display.
- `created_at` (DateTime): Timestamp.

**Table: threat_actors**
- `id` (String, PK): UUID.
- `name` (String): e.g., "Lazarus Group".
- `country` (String): e.g., "North Korea".
- `description` (String): Bio.
- `aliases` (String): Other known names.
- `threat_level` (String): HIGH, CRITICAL.

**Table: notes**
- `id` (String, PK): UUID.
- `indicator` (String, Indexed): The IOC this note belongs to.
- `author` (String): User who wrote it.
- `content` (String): Markdown body.
- `created_at` (DateTime): Timestamp.

---

## 6. INSTALLATION & SETUP GUIDE

**Prerequisites**
- Python 3.10+
- Node.js 18+
- PostgreSQL server running locally or via Docker.
- Redis server running locally or via Docker (Windows users can use Memurai or WSL).

**Environment Variables (`backend/.env`)**
```ini
DATABASE_URL=postgresql://postgres:password@localhost:5432/threatmap
REDIS_URL=redis://localhost:6379/0

# API Keys
VT_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
GREYNOISE_API_KEY=your_key
OTX_API_KEY=your_key
URLSCAN_API_KEY=your_key
SHODAN_API_KEY=your_key
GEMINI_API_KEY=your_key
```

**Step-by-Step Setup**
1. **Database:**
   - Create a postgres database named `threatmap`.
2. **Backend:**
   - `cd backend`
   - `python -m venv venv`
   - `.\venv\Scripts\activate` (Windows) or `source venv/bin/activate` (Mac/Linux)
   - `pip install -r requirements.txt`
   - `python -m uvicorn main:app --reload --port 8000`
3. **Frontend:**
   - `cd frontend`
   - `npm install`
   - `npm run dev`
4. **Redis:**
   - Ensure redis is running on port 6379.

---

## 7. KNOWN ISSUES & LIMITATIONS

- **Free Tier API Limits:** Heavy usage will rapidly exhaust the VirusTotal (4 requests/min) and Shodan quotas. The Redis cache mitigates this, but bulk scanning > 5 IOCs simultaneously on free tiers will result in HTTP 429 (Too Many Requests) errors.
- **Windows IPv6 Delay Issue:** Python `aiohttp` and `urllib` on Windows can sometimes experience 2-second delays resolving `localhost` via IPv6. Connecting explicitly to `127.0.0.1` or disabling IPv6 locally resolves this.
- **Gemini Quota:** Google Gemini free tier has a 15 Request Per Minute limit. If exceeded, the AI mitigation brief will fail gracefully and display a "Rate Limit Reached" fallback message.
- **URLScan Delays:** URLScan processes requests asynchronously. The backend waits up to 10 seconds, but if URLScan is under heavy load, the screenshot may timeout and not appear in the initial report.

---

## 8. FUTURE IMPROVEMENTS

- **SpiderFoot Integration:** Fully integrate the local SpiderFoot REST API into the dashboard to trigger deep OSINT footprinting directly from the UI without leaving ThreatMap.
- **Cloud Deployment:** Containerize the application using Docker Compose and deploy to Railway or AWS ECS for high availability.
- **RBAC (Role-Based Access Control):** Implement JWT authentication to allow multiple analysts to maintain private watchlists and notes.
- **Webhook Alerts:** Push notifications to Slack/Discord when an IOC on the watchlist suddenly spikes in its risk score.

---

## 9. CREDITS & ACKNOWLEDGEMENTS

**APIs & Services:**
- VirusTotal (Alphabet)
- AbuseIPDB
- GreyNoise Intelligence
- URLScan.io
- AlienVault OTX (AT&T Cybersecurity)
- Shodan
- Google DeepMind (Gemini)
- IP-API

**Open Source Libraries & Frameworks:**
- **FastAPI & Pydantic:** For the lightning-fast Python backend.
- **Next.js & React:** For the frontend architecture.
- **Tailwind CSS & Framer Motion:** For the premium $10,000-grade UI aesthetics and animations.
- **SQLAlchemy:** For robust database management.
- **Leaflet & React-Leaflet:** For interactive geospatial mapping.
