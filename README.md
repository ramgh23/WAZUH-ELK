# WAZUH-ELK
SIEM Implementation by integrationg WAZUH &amp; ELK. Monitoring success and failure of login events and creating custom DOS rule to record DOS events

Objective
The objective of this report is to explore the implementation of a SIEM (Security Information and Event Management) system by integrating ELK (Elasticsearch, Logstash, and Kibana) with Wazuh for enhanced security monitoring. The report details the setup of the SIEM environment, the execution of a DoS attack using hping3, and the analysis of security events captured in the Wazuh event dashboard. This project aims to demonstrate the effectiveness of SIEM solutions in detecting and responding to cybersecurity threats in real time.

Introduction
In today's evolving cybersecurity landscape, organizations face constant threats, including Denial-of-Service (DoS) attacks, which can disrupt services and cause significant downtime. SIEM solutions play a crucial role in real-time threat detection, log management, and incident response.
This report focuses on implementing a SIEM solution using Wazuh integrated with ELK to monitor security events effectively. Wazuh serves as an open-source security platform that collects and analyzes logs, while ELK provides log storage, processing, and visualization. To evaluate the effectiveness of this setup, a DoS attack will be conducted using hping3 on a monitored Windows system, and security logs will be analyzed in Wazuh’s event dashboard to detect the attack.

What is SIEM?
SIEM (Security Information and Event Management) is a cybersecurity tool that helps organizations collect, analyze, and respond to security threats in real-time. It works like a smart security system that monitors all activities happening in a network and alerts security teams if something suspicious happens.
SIEM has two main functions:
 Security Information Management (SIM) – Stores and analyzes security logs for reports.
  Security Event Management (SEM) – Detects threats, correlates data, and sends alerts.

Purpose of SIEM
SIEM gathers data from firewalls, servers, endpoints, and cloud systems and looks for signs of cyber threats.
I.	Collects logs from different devices.
II.	Finds suspicious patterns by analyzing events.
III.	Sends alerts when a potential attack is detected.
IV.	Helps investigate security incidents.
V.	Ensures compliance with laws like GDPR, PCI-DSS, HIPAA

ELK Integration with Wazuh
Integrating Wazuh with ELK (Elasticsearch, Logstash, and Kibana) provides a comprehensive security monitoring solution by combining log analysis, threat detection, and visualization.
1. Overview of Integration
•	Wazuh: An open-source security platform that provides log analysis, threat detection, intrusion detection (HIDS), and compliance monitoring.
•	ELK Stack: A log management and visualization platform composed of:
o	Elasticsearch: Stores and indexes logs efficiently.
o	Logstash: Collects, processes, and forwards logs from different sources.
o	Kibana: Visualizes security events with dashboards and analytics.
By integrating Wazuh with ELK, security teams can centralize and analyze logs from multiple endpoints, detect anomalous activities, and respond to security incidents in real-time.

Benefits of ELK Integration with Wazuh
•	Real-time Threat Detection: Detects anomalies, malware, DoS attacks, and security breaches.
•	Log Centralization & Correlation: Gathers logs from multiple sources for enhanced visibility.
•	Compliance Monitoring: Helps meet regulatory requirements (PCI DSS, GDPR, HIPAA, etc.).
•	Automated Alerting & Response: Generates alerts and supports incident investigation using dashboards.

Role of Wazuh in Detecting DoS Attacks
Wazuh, an open-source Security Information and Event Management (SIEM) tool, helps in monitoring, analyzing, and detecting security threats in real time. When integrated with the ELK (Elasticsearch, Logstash, Kibana) stack, Wazuh enhances visibility into system logs and network activity, making it an effective solution for detecting and responding to DoS attacks.

How Wazuh Detects DoS Attacks:
•	Log Monitoring: Wazuh collects and analyzes system, application, and network logs to detect unusual activity.
•	Behavioral Analysis: It can identify anomalies such as excessive requests from a single IP, which may indicate a DoS attempt.
•	Real-time Alerts: Wazuh generates alerts for abnormal network traffic, helping security teams take action.
