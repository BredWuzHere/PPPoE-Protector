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




how to run
1. prepare the PS4 linux installation
- use your usual method to install or boot Arch Linux or Debian on the PS4 I will not provide jailbreak or exploit instructions.
- ensure the system has network connectivity to the isolated lab network and you can open a shell as root or via sudo.

2. install prerequisites
- update package list and install Python 3 and pip

on Arch (command lines)
sudo pacman -Syu python pythonpip

on (Debian or Ubuntu)
sudo apt update && sudo apt install -y python3 python3pip
install scapy and tcpdump if you want to capture traffic
sudo pip3 install scapy
sudo pacman -S tcpdump

install firewall tools for auto blocking if desired
sudo pacman -S nftables
or ensure iptables is present as fallback
sudo pacman -S iptables

3. copy the protector script
- transfer pppoe_protector.py the defensive script to the PS4 Linux filesystem for example usr local bin pppoe_protector.py
- make it executable
- sudo chmod +x usr local bin pppoe_protector.py

4. configure a safe working directory and logs
- Create a log directory
- sudo mkdir -p var log pppoe_protector
- sudo chown yourusername var log pppoe_protector

5. run in alert only first test
- start the protector in alert only mode first do NOT enable auto block
sudo python3 usr local bin pppoe_protector.py iface eth0
replace iface eth0 with the actual interface name use ip link to list interfaces

6. run as a systemd service (optional)
Create etc systemd system pppoe_protector.service with these contents
(unit)
Description=PPPoE Protector
After=network.target

(service)
ExecStart=/usr/bin/python3 /usr/local/bin/pppoe_protector.py iface eth0
Restart=on-failure
User=root

[install]
WantedBy=multi-user.target

Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now pppoe_protector.service

7. enable auto block only after tuning
When you are confident the alerts are valid and not false positives restart with auto block and a short block time for testing
sudo python3 usr local bin pppoe_protector.py iface eth0 autoblock blocktime 120

protector log output (console or file), u should see warnings such as:
- Oversized PPP LCP from ...
- ICMPv6 echo flood from ...
- High ND (NS/NA) rate from ...
