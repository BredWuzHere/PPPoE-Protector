PPPoE Protector — Defensive Tool (Inspired by Andy Nguyen’s ppwn)
This project was created after studying Andy Nguyen’s ppwn PlayStation 4 research, which demonstrated a class of kernel heap overflow techniques using PPPoE and IPv6 neighbor/ICMP traffic.
The goal of this repository is defensive: it implements network-layer detection and mitigation for the noisy behaviors commonly used in that exploit,
(oversized PPP LCP, large PPPoE discovery tags, ICMPv6 flood/grooming patterns, excessive ND messages).

Important: This code does not contain exploit code, kernel patches, or payloads. It is designed to help protect devices by :
- Monitoring for suspicious PPPoE / PPP LCP / ICMPv6 / ND traffic patterns.
- Logging and alerting on anomalous behavior.
- Optionally applying non-destructive firewall rules to block offending sources at the host/gateway.

Intended use: research, learning, and defense in environments you own or are authorized to test. Do not use against devices you do not control or have permission to protect.
Credits: Andy Nguyen — thank you for the research and inspiration. This project was made for fun and learning; it implements defensive measures informed by that research.
