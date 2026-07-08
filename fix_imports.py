import os

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    new_content = content.replace('from backend.', 'from ')
    new_content = new_content.replace('import backend.', 'import ')
    
    if new_content != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Updated {filepath}")

for root, _, files in os.walk('c:/ThreatMap/backend'):
    for file in files:
        if file.endswith('.py'):
            process_file(os.path.join(root, file))
