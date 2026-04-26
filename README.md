# python-firewall
This is a simple python program that simulates a basic firewall decision process. This program evaluates network traffic records against a list of firewall rules and determine whether each record should be allowed or denied.

As of now this code is able to: \
•	identify important fields in network traffic \
•	distinguish between TCP and UDP \
•	explain how firewall rules are matched \
•	write a Python program that applies rule based logic to traffic \
•	interpret common ports such as HTTP, HTTPS, DNS, SSH, RDP, and VPN related ports 

What it does is: \
•	read each traffic record \
•	compare it to the firewall rules in order \
•	determine whether the record is ALLOW or DENY \
•	print the result in a readable format 

The traffic is outputed in this format: \
10.4.5.32 -> 192.168.2.30 UDP/51820 (Wireguard) [Possible VPN (WireGuard)] : ALLOW \
10.4.5.33 -> 192.168.2.31 TCP/3389 (RDP) : DENY \
At the end I made sure to include how many flows were allowed/denied and flagged potential VPN users.

In this github I included rules and traffic in csv format in case you want to try it out!
