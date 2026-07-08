import sys
import traceback
sys.path.append('c:\\ThreatMap\\backend')

from models.database import SessionLocal, Scan
from routers.export import _export_pdf, _export_json, _export_csv

try:
    db = SessionLocal()
    scan = db.query(Scan).first()
    if not scan:
        print("No scans found")
        sys.exit(0)
        
    print('Scan ID:', scan.id)
    
    print('Testing JSON...')
    _export_json(scan)
    print('JSON OK')
    
    print('Testing CSV...')
    _export_csv(scan)
    print('CSV OK')
    
    print('Testing PDF...')
    _export_pdf(scan)
    print('PDF OK')
except Exception as e:
    traceback.print_exc()
