# Research-Project

IoMT Shield — Portable Edge Security Framework for IoMT

IoMT Shield is a portable security gateway designed to protect Internet of Medical Things (IoMT) environments used in remote patient monitoring (RPM). The system sits at the edge (Raspberry Pi 4) and provides secure data delivery, real-time intrusion detection, threat intelligence, and automated mitigation.

What it does

* Secure Telemetry Pipeline (ESP32 → Pi): Medical device telemetry is transmitted to the gateway with lightweight encryption and integrity validation to reduce data exposure during transport.
* TinyML Intrusion Detection (Edge IDS): A lightweight deep learning model (TinyMLP) runs on the Raspberry Pi to classify traffic in real time as BENIGN / SUSPICIOUS / ATTACK, while maintaining low latency and minimal resource overhead.
* Honeypot Threat Intelligence: A local honeypot attracts attacker activity (e.g., scans, brute-force attempts) and records useful threat indicators for analysis and dataset generation.
* SDN + Dashboard Response Layer: Detection events are written to structured logs (e.g., events.jsonl) that can feed an SDN controller for automatic blocking/quarantine and a dashboard for real-time visibility and reporting.

Why it matters

IoMT systems handle sensitive health data and often operate under strict resource constraints. IoMT Shield delivers practical, deployable edge security by combining lightweight cryptography, TinyML inference, and automated response mechanisms in a single portable gateway.
