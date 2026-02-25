import vt
import asyncio
import requests
import json
import sys
import socket

def ip_function():
    IP_MAIN = input("Enter IP: ")

    print("\n")
    # Resolve IP
    try:
        hostname = socket.gethostbyaddr(IP_MAIN)
        print(f"{IP_MAIN} resolves to {hostname[0]}")
    except socket.herror:
        print(f"Could not resolve hostname for {IP_MAIN}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    print("\n")

    print("*****Virus Total*****")
    # Replace with your VirusTotal API key
    API_KEY = "Replace with your VirusTotal API key"

    async def check_ip_reputation():
        client = vt.Client(API_KEY)

        try:
            ip_object = await client.get_object_async(f"/ip_addresses/{IP_MAIN}")

            # Extract and print relevant information
            print(f"Reputation Score:            {ip_object.reputation}")
            print(f"Autonomous System Owner:     {ip_object.as_owner}")
            print(f"Country:                     {ip_object.country}")
            
            # Check last analysis stats
            last_analysis_stats = ip_object.last_analysis_stats
            print(f"\033[32mHarmless Detections:    {last_analysis_stats.get('harmless', 0)}\033[32m")
            print(f"\033[31mMalicious Detections:   {last_analysis_stats.get('malicious', 0)}\033[0m")
            print(f"\033[33mSuspicious Detections:  {last_analysis_stats.get('suspicious', 0)}\033[0m")
            print(f"Undetected:     {last_analysis_stats.get('undetected', 0)}")

        except vt.APIError as e:
            print(f"An API error occurred: {e}")
        finally:
            await client.close_async()

    
    asyncio.run(check_ip_reputation())

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{IP_MAIN}"

    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        
        # Check categories related to VPN, Proxy, Tor
        as_owner = attributes.get("as_owner", "Unknown")
        tags = attributes.get("tags", [])

        if "tor" in tags:
            print("Classification: TOR exit node")
        elif "vpn" in tags:
            print("Classification: VPN")
        elif "proxy" in tags:
            print("Classification: Proxy")
        else:
            print("Classification: No VPN/Proxy/TOR detected")
    else:
        print(f"Error: Unable to fetch data (status code {response.status_code})")

    print("\n")
    print("*****Abuse IP*****")


    def check_ip_abuse(ip_address, api_key):
        # Lookup Abusipdb
        url = f"https://api.abuseipdb.com/api/v2/check"
        
        querystring = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }
        
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        
        try:
            response = requests.get(url, headers=headers, params=querystring)
            response.raise_for_status() 
            
            data = response.json().get('data', {})
            return data

        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return None

    # Replace with your AbuseIPDB API key
    API_KEY = "Replace with your AbuseIPDB API key"

    ip_info = check_ip_abuse(IP_MAIN, API_KEY)

    if ip_info:
        print(f"Abuse Confidence Score: {ip_info['abuseConfidenceScore']}")
        print(f"Total Reports: {ip_info['totalReports']}")
        print(f"Country: {ip_info['countryCode']}")
        print(f"ISP: {ip_info['isp']}")



    print("\n")
    print("*****Whois Lookup*****")


    # Replace with your IP2location API key
    API_KEY = "Replace with your IP2location API key"
    BASE_URL = "https://api.ip2location.io"

    def ip_lookup(ip_address):
        params = {
            "key": API_KEY,
            "ip": ip_address,
            "format": "json"
        }

        response = requests.get(BASE_URL, params=params, timeout=10)
        response.raise_for_status()
        return response.json()


    
    ip = IP_MAIN
    result = ip_lookup(ip)

    print("AS:", result.get("as"))
    print("Country:", result.get("country_name"))
    print("Region:", result.get("region_name"))
    print("City:", result.get("city_name"))
    print("ISP:", result.get("isp"))
    print("ASN:", result.get("asn"))
    print("Timezone:", result.get("time_zone"))
    print("Fraud Score:", result.get("fraud_score"))
    print("Proxy Type:", result.get("proxy.proxy_type"))

    vt_link = f"https://www.virustotal.com/gui/ip-address/{IP_MAIN}"
    abuse_link = f"https://www.abuseipdb.com/check/{IP_MAIN}"
    print("\n***** Lookup Links *****")
    print(vt_link)
    print(abuse_link)



if __name__ == "__main__":

    ip_function()
