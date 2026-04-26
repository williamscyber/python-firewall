# python-firewall
This project is a Python based simulation of a basic firewall decision engine. It evaluates network traffic records against a set of firewall rules and determines whether each flow should be **allowed or denied**.

As of now this code is able to: \
•	identify important fields in network traffic \
•	distinguish between TCP and UDP \
•	explain how firewall rules are matched \
•	write a Python program that applies rule based logic to traffic \
•	interpret common ports such as HTTP, HTTPS, DNS, SSH, RDP, and VPN related ports 

What it does is: \
•	reads the traffic and rule data from CSV files\
•	compares it to the firewall rules in order (top-down) \
•	applies matching logic: exact match OR wildcard (`ANY`) \
•	prints the result in a readable format 

The traffic is outputed in this format: \
10.4.5.32 -> 192.168.2.30 UDP/51820 (Wireguard) [Possible VPN (WireGuard)] : ALLOW \
10.4.5.33 -> 192.168.2.31 TCP/3389 (RDP) : DENY \
At the end I made sure to include how many flows were allowed/denied and flagged potential VPN users.

I plan to add:
•	Add IP/subnet filtering \
•	Implement rule priority levels \
•	Support stateful inspection \
•	Add logging and visualization \
  
In this github I included rules and traffic in csv format in case you want to try it out!
