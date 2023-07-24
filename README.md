# Babble - Passive discovery
TL;DR : Passive discovery from broadcast network noise.

![screenshot](./images/screen.png)

Babble is a Python script that parses packets of protocols that are common in entreprise LANs. It then logs the hostnames/domains found in a pretty table and in greppable format.
The advantages of Babble are the following :
- Stealth : no network interaction
- Easily runs in background
- Supports Linux network interfaces and  `.pcap` files
- Greppable output easily exploitable with awk

Babble can be useful in early phases of offensive security audits, when the auditors have no foothold but still want to discover domains/hosts/services stealthily.

## Installation
Requirements :
- pyshark
- rich
```
python -m pip install -r requirements.txt 
```
## Usage
```
babble.py -i eth0
babble.py -f dump.pcapng

# Enable DNS
babble.py -i eth0 -d

# Greppable
babble.py -i eth0 -g
```

## Supported Protocols
- MDNS
- BROWSER (over NETBIOS : parsed too)
- DHCPv6
- LLDP
- CDP
- DNS (default : Disabled)
- NETBIOS

Don't hesitate to ask support for other relevant protocols

## TODO
- Save data to file, so several captures can be merged
- CIDR analysis
- Progress bar for pcap ingestion
- Last seen column (last time a packet was seen for a given query)
