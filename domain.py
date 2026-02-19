import requests
import socket
from datetime import datetime


def domain_function():
    def vt_domain_lookup(domain):
        # Replace with your VirusTotal API key
        VT_API_KEY = "Replace with your VirusTotal API key"
        VT_URL = "https://www.virustotal.com/api/v3/domains/{}"

        headers = {
            "x-apikey": VT_API_KEY
        }

        response = requests.get(VT_URL.format(domain), headers=headers)
        print("\n")
        # Resolve to IP
        try:
            ip_address = socket.gethostbyname(domain_input)
            print(f"The IP address of {domain_input} is {ip_address}")
        except socket.gaierror:
            print(f"Failed to resolve domain: {domain}")

        if response.status_code != 200:
            print(f"[!] Error: {response.status_code} - {response.text}")
            return

        data = response.json()["data"]["attributes"]

        stats = data.get("last_analysis_stats", {})
        reputation = data.get("reputation", "N/A")
        registrar = data.get("registrar", "Unknown")
        categories = data.get("categories", {})
        whois = data.get("whois", "N/A")

        creation_date = data.get("creation_date")
        if creation_date:
            creation_date = datetime.utcfromtimestamp(creation_date).strftime("%Y-%m-%d")

        print("\n***** VirusTotal Domain Report *****\n")
        print(f"Domain        : {domain}")
        print(f"Reputation    : {reputation}")
        print(f"Registrar     : {registrar}")
        print(f"Created On    : {creation_date}")

        print("\n*** Analysis Stats ***")
        print(f"Malicious     : {stats.get('malicious', 0)}")
        print(f"Suspicious    : {stats.get('suspicious', 0)}")
        print(f"Harmless      : {stats.get('harmless', 0)}")
        print(f"Undetected    : {stats.get('undetected', 0)}")

        print("\n*** Categories ***")
        if categories:
            for vendor, category in categories.items():
                print(f"{vendor}: {category}")
        else:
            print("No categories available")

        print("\n*** WHOIS ***")
        print(whois)

    domain_input = input("Enter domain: ").strip()
    vt_domain_lookup(domain_input)

    print("\n")
    vt_link = f"https://www.virustotal.com/gui/domain/{domain_input}"
    print(vt_link)
if __name__ == "__main__":
    domain_function()