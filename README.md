# oneix-1.1
malware analysis artificial intelligence

Web-Based Threat Intelligence & MITRE Mapping System
An advanced, browser-based security tool designed to analyze behavioral log files and identify malicious activities using rule-based detection mapped to the MITRE ATT&CK® framework.


This project simulates a Security Operations Center (SOC) dashboard. It allows analysts to upload system logs, identify high-risk behaviors, and receive automated incident response recommendations. Developed as a final-year BCA project, it focuses on high performance and security depth without requiring heavy backend resources.

 Key Features
 1]Behavioral Detection Engine: Uses optimized Regular Expressions (RegEx) to identify IoCs (Indicators of Compromise).
 2]MITRE ATT&CK Mapping: Automatically maps detected threats to specific Technique IDs (e.g., T1059, T1112).
 3]Dynamic Risk Scoring: Calculates a weighted risk score ($0-100\%$) based on threat severity.
 4]Attack Timeline: Visualizes the chronological flow of malicious events to help identify the attack lifecycle.
 5]Incident Reporting: One-click generation of professional text-based incident reports.
 
  Tech StackFrontend: 
  HTML5
  CSS3 (Custom SOC Dark Theme)
  Logic: Vanilla JavaScript (ES6+).
  
  Performance: 
  Client-side processing optimized for systems with 8GB RAM.
