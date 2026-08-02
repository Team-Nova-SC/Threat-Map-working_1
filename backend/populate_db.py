import sys
import os

# Add the backend directory to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models.database import init_db
from services.mitre_service import sync_threat_actors

print("Initializing DB...")
init_db()
print("Syncing Threat Actors...")
sync_threat_actors()
print("Done!")
