import csv

def load_csv_dicts(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

#setup for support with ANY for protocol and port
def matches_rule(flow, rule):
    return (
        (rule["protocol"] == "ANY" or rule["protocol"] == flow["protocol"]) and
        (rule["port"] == "ANY" or rule["port"] == flow["port"])
    )

def evaluate_flow(flow, rules):
    for rule in rules:
        if matches_rule(flow, rule):
            return rule["action"]
    return "DENY"

#dictionary for common ports
#I added some extra services that aren't used in the csv as well
services = {
    #common web traffic
    "80": "HTTP",
    "443": "HTTPS",
    "8080": "HTTP ALT",
    "8443": "HTTPS ALT",
    #common dns/network basics
    "53": "DNS",
    "67": "DHCP Server",
    "68": "DHCP Client",
    "123": "NTP",
    #common remote access
    "22": "SSH",
    "3389": "RDP",
    "5900": "VNC",
    #common email
    "25": "SMTP",
    "110": "POP3",
    "143": "IMAP",
    "587": "SMTP Submission",
    "993": "IMAPS",
    "995": "POP3S",
    #common directory services
    "389": "LDAP",
    "636": "LDAPS",
}

#dictionary for possible VPN ports
vpns = {
    "500": "Possible VPN (IKE/IPsec)",
    "4500": "Possible VPN (IPsec NAT-T)",
    "1194": "Possible VPN (OpenVPN)",
    "51820": "Possible VPN (WireGuard)",
    "1701": "Possible VPN (L2TP)",
    "1723": "Possible VPN (PPTP)"
}

def main():

    #deleted the other to keep my code clean
    traffic = load_csv_dicts("traffic_expanded.csv")
    rules = load_csv_dicts("rules_expanded.csv")

    #counters for deny/allow
    allowed = 0
    denied = 0

    for flow in traffic:
        decision = evaluate_flow(flow, rules)

        #used to count flows being denied/allowed
        if decision == 'ALLOW':
            allowed += 1
        else:
            denied += 1

        port = flow["port"]
        service = services.get(port, "Unknown Service")  #print service name for common port
        vpn = vpns.get(port) #flags possible vpn traffic
        vpn_text = f" [{vpn}]" if vpn else ""
        print(
            f'{flow["src_ip"]} -> {flow["dst_ip"]} '
            f'{flow["protocol"]}/{flow["port"]} ({service}){vpn_text} : {decision}'
        )

    #print at end of how many flow allowed/denied
    print("\nAllowed:", allowed)
    print("Denied:", denied)


if __name__ == "__main__":
    main()

#Reflection Question put as a comment in code use “#” to comment python code
#Which ports in this dataset are commonly associated with VPNs, and why might a firewall allow some of them but deny others?
#The ports that this dataset used for VPN traffic the most were 500, 4500, 1194, and 51820.
#The firewall might allow some VPN ports because it allows for secure communication and lots of times is legit.
#The firewall might deny some VPN ports because they are outdated/insecure (like PPTP), go against company policy, or are being used to bypass security controls/hide IP.