import csv

def load_csv_dicts(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

#Setup for support with ANY for protocol and port
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

#Dictionary for common ports
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

#Dictionary for possible VPN ports
vpns = {
    "500": "Possible VPN (IKE/IPsec)",
    "4500": "Possible VPN (IPsec NAT-T)",
    "1194": "Possible VPN (OpenVPN)",
    "51820": "Possible VPN (WireGuard)",
    "1701": "Possible VPN (L2TP)",
    "1723": "Possible VPN (PPTP)"
}

def main():

    #Call for CSV files
    traffic = load_csv_dicts("traffic_expanded.csv")
    rules = load_csv_dicts("rules_expanded.csv")

    #Counters for allow/deny
    allowed = 0
    denied = 0

    for flow in traffic:
        decision = evaluate_flow(flow, rules)

        if decision == 'ALLOW':
            allowed += 1
        else:
            denied += 1

        port = flow["port"]
        service = services.get(port, "Unknown Service") 
        vpn = vpns.get(port) 
        vpn_text = f" [{vpn}]" if vpn else ""
        print(
            f'{flow["src_ip"]} -> {flow["dst_ip"]} '
            f'{flow["protocol"]}/{flow["port"]} ({service}){vpn_text} : {decision}'
        )

    print("\nAllowed:", allowed)
    print("Denied:", denied)


if __name__ == "__main__":
    main()