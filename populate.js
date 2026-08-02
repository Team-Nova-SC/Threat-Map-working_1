const sqlite3 = require('sqlite3').verbose();
const https = require('https');
const path = require('path');

const dbPath = path.join(__dirname, 'backend', 'threatmap.db');
const db = new sqlite3.Database(dbPath);

https.get('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json', (res) => {
    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => {
        const json = JSON.parse(data);
        const intrusionSets = json.objects.filter(obj => obj.type === 'intrusion-set');
        
        db.serialize(() => {
            const stmt = db.prepare(`INSERT OR REPLACE INTO threat_actors 
                (id, name, aliases, country, description, threat_level, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`);
            
            let count = 0;
            for (const iset of intrusionSets) {
                const stix_id = iset.id;
                const name = iset.name;
                const description = iset.description || '';
                const aliases = (iset.aliases || []).join(', ');
                
                let country = 'Unknown';
                if (description.includes('Russia') || description.includes('Russian')) country = 'Russia';
                else if (description.includes('China') || description.includes('Chinese')) country = 'China';
                else if (description.includes('North Korea') || description.includes('DPRK')) country = 'North Korea';
                else if (description.includes('Iran') || description.includes('Iranian')) country = 'Iran';
                
                const threat_level = country !== 'Unknown' ? 'CRITICAL' : 'HIGH';
                
                stmt.run(stix_id, name, aliases, country, description, threat_level);
                count++;
            }
            stmt.finalize();
            console.log(`Inserted/Updated ${count} threat actors.`);
        });
        db.close();
    });
});
