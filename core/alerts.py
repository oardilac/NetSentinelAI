# Alert system for logging and displaying detected threats in the IDS.
# Written by: @dukebismaya

import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LOG_PATH = os.path.join(BASE_DIR, "logs", "ids_alerts.log")

class AlertSystem:
    def __init__(self, log_file=DEFAULT_LOG_PATH):
        if log_file is None:
            current_file_path = os.path.abspath(__file__) 
            core_dir = os.path.dirname(current_file_path)
            
            # 3. Get the project root (one level up from core)
            project_root = os.path.dirname(core_dir)
            
            # 4. Point to logs/ inside that root
            self.log_file = os.path.join(project_root, "logs", "ids_alerts.log")
        else:
            self.log_file = log_file
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        # Clear previous logs on startup
        with open(self.log_file, 'w') as f:
            f.write('')
    
    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'threat_type': threat['type'],
            'rule_or_score': threat.get('rule', round(threat.get('score', 0), 2)),
            'source_ip': packet_info['source_ip'],
            'destination_ip': packet_info['destination_ip'],
        }
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(alert) + '\n')
        
        print(f"🚨 ALERT TRIGGERED: {alert['threat_type']} detected from {alert['source_ip']} to {alert['destination_ip']} at {alert['timestamp']} with confidence {threat.get('confidence', 0):.2f}")