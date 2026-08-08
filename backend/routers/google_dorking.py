import urllib.parse
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional

router = APIRouter(prefix="/tools", tags=["Google Dorking"])

class GoogleDorkRequest(BaseModel):
    target: str
    mode: str = "domain"  # domain, company, email, keyword

class DorkItem(BaseModel):
    name: str
    category: str
    query: str
    url: str
    description: str
    expected_findings: str

class GoogleDorkResponse(BaseModel):
    target: str
    mode: str
    total_dorks: int
    dorks: List[DorkItem]
    explanation: dict

@router.post("/google-dorks", response_model=GoogleDorkResponse)
async def generate_google_dorks(req: GoogleDorkRequest):
    target = req.target.strip()
    mode = req.mode.strip().lower()

    if not target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")

    if mode not in {"domain", "company", "email", "keyword"}:
        raise HTTPException(status_code=400, detail="Mode must be domain, company, email, or keyword")

    cleaned = target.replace("https://", "").replace("http://", "").strip("/")
    if mode == "domain":
        cleaned = cleaned.split("/")[0]

    def google_url(query: str) -> str:
        return f"https://www.google.com/search?q={urllib.parse.quote_plus(query)}"

    raw_queries = []

    if mode == "domain":
        raw_queries = [
            (
                "Exposed PDF & Document Assets",
                "Exposed Documents",
                f"site:{cleaned} filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:ppt",
                "Locates indexed office documents and public PDFs on the target domain.",
                "Internal company memos, financial reports, architectural diagrams, staff rosters."
            ),
            (
                "Open Directory Listings",
                "Directory Indexing",
                f"site:{cleaned} intitle:\"index of\" OR intitle:\"directory listing\"",
                "Identifies web server directories where directory browsing is enabled.",
                "Raw server folder contents, unlinked assets, scripts, static backups."
            ),
            (
                "Administrative & Login Portals",
                "Admin & Auth",
                f"site:{cleaned} inurl:login OR inurl:admin OR inurl:portal OR inurl:dashboard OR intitle:\"login\"",
                "Finds web management panels, SSO portals, and user sign-in forms.",
                "Staging login screens, CMS admin panels (wp-admin, cpanel), internal webapps."
            ),
            (
                "Configuration & Environment Files",
                "Sensitive Files",
                f"site:{cleaned} ext:env OR ext:yaml OR ext:conf OR ext:ini OR ext:config OR ext:xml",
                "Queries indexed configuration settings and environment variable files.",
                "API tokens, database credentials, internal service hostnames, secret keys."
            ),
            (
                "Database Dumps & Backup Archives",
                "Backups & DB",
                f"site:{cleaned} ext:sql OR ext:db OR ext:bak OR ext:old OR ext:backup OR ext:zip OR ext:tar.gz",
                "Searches for archived database tables and backup archives left in public web roots.",
                "SQL table dumps, site source backups, legacy database exports."
            ),
            (
                "Error Logs & Stack Trace Disclosures",
                "Information Leakage",
                f"site:{cleaned} \"stack trace\" OR \"syntax error\" OR \"fatal error\" OR \"SQL syntax error\" OR \"warning:\"",
                "Finds application crash dumps and verbose framework error messages indexed by crawlers.",
                "Database schema names, backend file paths, framework versions, query logic."
            ),
            (
                "Public Log Files",
                "Sensitive Files",
                f"site:{cleaned} ext:log OR inurl:log OR intitle:\"index of\" \"logs\"",
                "Locates web server access logs, application debug logs, and transaction logs.",
                "Client IP history, debug session tokens, error events, internal URLs."
            ),
            (
                "Exposed Git & Subversion Metadata",
                "Source Code",
                f"site:{cleaned} inurl:.git OR inurl:.svn OR inurl:.env",
                "Checks if version control metadata directories are publicly accessible.",
                "Git commit history, developer notes, source repository structure."
            ),
            (
                "Cloud Storage & S3 Buckets",
                "Cloud Assets",
                f"site:{cleaned} \"s3.amazonaws.com\" OR \"storage.googleapis.com\" OR \"blob.core.windows.net\"",
                "Finds direct references to cloud storage buckets connected to the target.",
                "Publicly downloadable cloud assets, media repositories, backup buckets."
            ),
            (
                "Indexed Subdomain Discovery",
                "Footprinting",
                f"site:*.{cleaned} -site:www.{cleaned}",
                "Discovers indexed subdomains by excluding the main www host.",
                "Dev/staging subdomains, api endpoints, internal tools, legacy subdomains."
            ),
            (
                "WordPress / CMS Specific Footprints",
                "CMS Exposure",
                f"site:{cleaned} inurl:wp-content OR inurl:wp-includes OR inurl:readme.html",
                "Checks for CMS framework footprints and default documentation files.",
                "Plugin directories, vulnerable theme versions, CMS version numbers."
            ),
            (
                "Sensitive Keyword Exposure",
                "Sensitive Content",
                f"site:{cleaned} \"confidential\" OR \"internal use only\" OR \"secret\" OR \"api_key\"",
                "Scans indexed pages for sensitive enterprise classification markers.",
                "Privileged documents, API documentation meant for internal devs."
            )
        ]
    elif mode == "email":
        raw_queries = [
            (
                "Exact Email Mentions",
                "Brand Exposure",
                f"\"{cleaned}\"",
                "Finds all web pages indexed by Google containing this exact email address.",
                "Public forum posts, press releases, staff listings, contact directories."
            ),
            (
                "Paste Site & Code Dumps",
                "Credential Leaks",
                f"\"{cleaned}\" site:pastebin.com OR site:ghostbin.com OR site:gist.github.com",
                "Checks public code pastebins for leaked email references.",
                "Raw credential dumps, configuration pastes, code snippets."
            ),
            (
                "Breach & Leak Context",
                "Credential Leaks",
                f"\"{cleaned}\" password OR leaked OR breach OR combo",
                "Searches for instances where the email appears alongside breach keywords.",
                "Publicly indexed breach notifications, leak summaries."
            ),
            (
                "Document & Attachment Mentions",
                "Exposed Documents",
                f"\"{cleaned}\" filetype:pdf OR filetype:doc OR filetype:xls",
                "Locates published documents authoring or referencing this email.",
                "PDF reports, contract documents, academic papers, meeting minutes."
            )
        ]
    elif mode == "company":
        raw_queries = [
            (
                "Corporate Document Footprint",
                "Exposed Documents",
                f"\"{cleaned}\" filetype:pdf OR filetype:ppt OR filetype:xls OR filetype:docx",
                "Searches for published whitepapers, slide decks, and financial spreadsheets.",
                "Quarterly financial decks, internal policies, vendor contracts."
            ),
            (
                "Infrastructure & Cloud Clues",
                "Footprinting",
                f"\"{cleaned}\" \"AWS\" OR \"Azure\" OR \"Kubernetes\" OR \"Docker\" OR \"Terraform\"",
                "Identifies job posts, case studies, and articles describing the company's tech stack.",
                "Cloud provider usage, CI/CD tools, DevOps architecture details."
            ),
            (
                "Exposed Corporate Portals",
                "Admin & Auth",
                f"\"{cleaned}\" inurl:login OR inurl:admin OR inurl:portal OR inurl:sso",
                "Finds branded employee portals and external partner login screens.",
                "VPN login pages, partner portals, webmail access points."
            ),
            (
                "Public Code Repositories",
                "Source Code",
                f"\"{cleaned}\" site:github.com OR site:gitlab.com OR site:bitbucket.org",
                "Discovers public repositories associated with the company.",
                "Open-source projects, accidental company code commits, public API clients."
            ),
            (
                "Breach & Credential References",
                "Credential Leaks",
                f"\"{cleaned}\" leaked OR breach OR credentials OR database dump",
                "Searches indexed security intelligence for breach references.",
                "Third-party breach summaries, threat intelligence reports mentioning company."
            )
        ]
    else:  # keyword
        raw_queries = [
            (
                "Exact Match Keyword Search",
                "Brand Exposure",
                f"\"{cleaned}\"",
                "Finds exact text matches indexed across public websites.",
                "Direct references in articles, forums, documentation."
            ),
            (
                "Associated Document Search",
                "Exposed Documents",
                f"\"{cleaned}\" filetype:pdf OR filetype:doc OR filetype:xls",
                "Locates documents containing the specific keyword.",
                "Public research papers, PDF guides, technical manuals."
            ),
            (
                "Code Repository References",
                "Source Code",
                f"\"{cleaned}\" site:github.com OR site:gitlab.com",
                "Checks open-source repositories for occurrences of the keyword.",
                "Open source code, project repositories, public scripts."
            ),
            (
                "Leaked Credential Context",
                "Credential Leaks",
                f"\"{cleaned}\" leak OR breach OR dump OR password",
                "Searches for the keyword in security disclosure context.",
                "Threat intelligence discussions, security disclosure advisories."
            )
        ]

    dorks = [
        DorkItem(
            name=name,
            category=cat,
            query=query,
            url=google_url(query),
            description=desc,
            expected_findings=expected
        )
        for name, cat, query, desc, expected in raw_queries
    ]

    explanation = {
        "how_it_works": (
            "Google Dorking utilizes advanced Google Search operators (e.g., site:, filetype:, inurl:, intitle:) "
            "to query Google's massive index of web pages. It filters public web crawler data to expose inadvertently "
            "indexed files, directories, configuration endpoints, and staging assets."
        ),
        "why_results_might_be_empty": [
            "1. Proper Indexing Security: The target website utilizes robots.txt or 'X-Robots-Tag: noindex' headers effectively.",
            "2. No Public Exposure: The target does not host or expose the specified file types (e.g., no exposed .env or .sql files).",
            "3. Web Application Firewall / Authentication: Content is protected behind authentication or SSO.",
            "4. Google Search CAPTCHA / Rate Limits: Google may present a bot challenge if automated queries are run rapidly.",
            "5. Indexing Delays: Newly published or updated pages may not have been crawled by Googlebot yet."
        ],
        "defensive_hardening": [
            "Add 'Disallow' directives in robots.txt for sensitive admin/staging directories.",
            "Enforce 'NOINDEX, NOFOLLOW' meta tags on internal or staging portals.",
            "Never place sensitive config files (.env, .git, .bak) in public web root directories.",
            "Use Google Search Console's URL Removal Tool to immediately de-index leaked assets."
        ]
    }

    return GoogleDorkResponse(
        target=target,
        mode=mode,
        total_dorks=len(dorks),
        dorks=dorks,
        explanation=explanation
    )
