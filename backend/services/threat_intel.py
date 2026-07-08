from sqlalchemy.orm import Session
from models.database import ThreatActor

def find_linked_actors(scan_data: dict, db: Session):
    """
    Searches through the raw scan data for tags/pulses matching known Threat Actor names or aliases.
    """
    actors = db.query(ThreatActor).all()
    if not actors:
        return []

    # Flatten some fields to search
    search_text = ""
    if "virustotal" in scan_data:
        vt = scan_data["virustotal"]
        search_text += " ".join(vt.get("tags", [])) + " "
        search_text += vt.get("suggested_threat_label", "") + " "
    
    if "alienvault" in scan_data:
        av = scan_data["alienvault"]
        pulses = av.get("pulse_info", {}).get("pulses", [])
        for p in pulses:
            search_text += p.get("name", "") + " "
            search_text += " ".join(p.get("tags", [])) + " "

    search_text = search_text.lower()
    
    linked = []
    for actor in actors:
        # Check primary name
        if actor.name.lower() in search_text:
            linked.append(actor)
            continue
        
        # Check aliases
        if actor.aliases:
            aliases = [a.strip().lower() for a in actor.aliases.split(",")]
            for a in aliases:
                if a and a in search_text:
                    linked.append(actor)
                    break
                    
    return linked
