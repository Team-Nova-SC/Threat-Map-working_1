import httpx
import logging
import logging
from models.database import ThreatActor, SessionLocal
import datetime
import datetime

logger = logging.getLogger(__name__)

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

async def sync_threat_actors():
    """
    Downloads the MITRE ATT&CK enterprise json and extracts Intrusion Sets (Threat Actors).
    Updates the database with the findings.
    """
    db = SessionLocal()
    logger.info("Starting MITRE ATT&CK Threat Actor synchronization...")
    try:
        transport = httpx.AsyncHTTPTransport(local_address='0.0.0.0')
        async with httpx.AsyncClient(transport=transport, timeout=30.0) as client:
            response = await client.get(MITRE_URL)
            response.raise_for_status()
            data = response.json()
            
        objects = data.get("objects", [])
        
        # Filter for intrusion-set objects
        intrusion_sets = [obj for obj in objects if obj.get("type") == "intrusion-set"]
        
        updated_count = 0
        for iset in intrusion_sets:
            stix_id = iset.get("id")
            name = iset.get("name")
            description = iset.get("description", "")
            aliases = ", ".join(iset.get("aliases", []))
            
            # Simple heuristic for country/origin (since MITRE description sometimes contains it)
            # Ideally we'd map this better, but we'll extract it if obvious
            country = "Unknown"
            if "Russia" in description or "Russian" in description:
                country = "Russia"
            elif "China" in description or "Chinese" in description:
                country = "China"
            elif "North Korea" in description or "DPRK" in description:
                country = "North Korea"
            elif "Iran" in description or "Iranian" in description:
                country = "Iran"
            
            # Upsert into database
            actor = db.query(ThreatActor).filter(ThreatActor.id == stix_id).first()
            if not actor:
                actor = ThreatActor(
                    id=stix_id,
                    name=name,
                    aliases=aliases,
                    description=description,
                    country=country,
                    threat_level="CRITICAL" if country != "Unknown" else "HIGH",
                    created_at=datetime.datetime.utcnow()
                )
                db.add(actor)
            else:
                actor.name = name
                actor.aliases = aliases
                actor.description = description
                actor.country = country
            updated_count += 1
            
        db.commit()
        logger.info(f"Successfully synced {updated_count} Threat Actors from MITRE.")
        
    except Exception as e:
        logger.error(f"Failed to sync MITRE ATT&CK data: {str(e)}")
    finally:
        db.close()
