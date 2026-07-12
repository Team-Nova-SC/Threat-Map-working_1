import urllib.parse

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/tools", tags=["Google Dorking"])


class GoogleDorkRequest(BaseModel):
    target: str
    mode: str = "domain"


@router.post("/google-dorks")
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

    if mode == "domain":
        queries = [
            ("Exposed documents", f"site:{cleaned} filetype:pdf OR filetype:doc OR filetype:xls"),
            ("Directory listings", f"site:{cleaned} intitle:\"index of\""),
            ("Login portals", f"site:{cleaned} inurl:login OR inurl:admin OR intitle:login"),
            ("Config files", f"site:{cleaned} ext:env OR ext:conf OR ext:ini OR ext:log"),
            ("Public backups", f"site:{cleaned} ext:bak OR ext:old OR ext:backup OR ext:sql"),
            ("Error disclosure", f"site:{cleaned} \"stack trace\" OR \"syntax error\" OR \"warning:\""),
            ("Sensitive keywords", f"site:{cleaned} password OR token OR secret OR api_key"),
            ("Subdomains indexed", f"site:*.{cleaned} -site:www.{cleaned}"),
            ("Git exposure", f"site:{cleaned} inurl:.git OR inurl:.svn"),
            ("Cloud storage mentions", f"site:{cleaned} \"s3.amazonaws.com\" OR \"storage.googleapis.com\""),
        ]
    elif mode == "email":
        queries = [
            ("Email mentions", f"\"{cleaned}\""),
            ("Paste mentions", f"\"{cleaned}\" site:pastebin.com OR site:ghostbin.com"),
            ("Credential context", f"\"{cleaned}\" password OR leaked OR breach"),
            ("Document mentions", f"\"{cleaned}\" filetype:pdf OR filetype:doc OR filetype:xls"),
        ]
    elif mode == "company":
        queries = [
            ("Public documents", f"\"{cleaned}\" filetype:pdf OR filetype:ppt OR filetype:xls"),
            ("Hiring tech clues", f"\"{cleaned}\" \"AWS\" OR \"Azure\" OR \"Kubernetes\""),
            ("Exposed portals", f"\"{cleaned}\" inurl:login OR inurl:admin OR inurl:portal"),
            ("Code mentions", f"\"{cleaned}\" site:github.com OR site:gitlab.com"),
            ("Leaks and breaches", f"\"{cleaned}\" leaked OR breach OR credentials"),
        ]
    else:  # keyword
        queries = [
            ("Exact keyword", f"\"{cleaned}\""),
            ("Documents", f"\"{cleaned}\" filetype:pdf OR filetype:doc OR filetype:xls"),
            ("Code repositories", f"\"{cleaned}\" site:github.com OR site:gitlab.com"),
            ("Past exposure", f"\"{cleaned}\" leak OR breach OR dump"),
        ]

    return {
        "target": target,
        "mode": mode,
        "dorks": [
            {"name": name, "query": query, "url": google_url(query)}
            for name, query in queries
        ],
        "note": "Queries are generated locally. Open links manually and only investigate assets you are authorized to assess.",
    }
