# Lookup_Tool
Python API lookup tool for IPs and Domains using VirusTotal, AbuseipDB, and IP2location. Run your lookups without having to open multiple browser tabs and have only one screen with all the information you need. You can use this template to build your own lookup tool. Feel free to customize with the information you need. You can also change the providers if you have ones the you prefer. If you do, please refer to their API documentation and update the code accordingly. I used free accounts with VirusTotal, Abuseipdb, and IP2location for my API keys.

<br><b>!!!IMPORTANT!!!</b></br>
Your API keys must be entered in domain.py and ip.py. In domain.py, 1 API key is needed for the VirusTotal domain lookup. for ip.py, 3 API keys are needed each for VirusTotal, Abuseipdb, and IP2location.

<br><b>!!!WARNING!!!</b></br>
Remove you API keys before sharing. Sharing with your API keys embedded can cause charges if your accounts are in paid subscriptions.

When using the tool, it will first try to resolve the IP or domain you entered.
This is followed by information from the lookup providers.
The last part gives you a URL of the lookup.

I chose VirusTotal, Abuseipdb, and IP2Location.io as you can make free accounts for these providers. If you have a paid account with any other provider, feel free to integrate. Keep in mind that most free API services have query limits.

<br><b>Query limits for free accounts:</b></br>
VirusTotal: 4 requests per minute and 500 requests per day
<br>Abuseipdb: 1000 requests per day</br>
ip2location.io: 1000 requests per day

<br><b>Usage:</b></br>
Save all 3 files in the same folder.
<br>Launch from master.py</br>
i - lookup IP
<br>d - lookup domain</br>
exit - exit program

You can compile the program once you have entered your API keys or you can keep using the tool as is without compiling.
