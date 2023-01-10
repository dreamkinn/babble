#!/usr/bin/env python3
# Author: @Dreamkinn
# Version: 1.0
# Description: Babble - a passive discovery tool that analyzes network noise

import argparse
from argparse import SUPPRESS
import os
from signal import signal, SIGINT

import pyshark
from rich.live import Live
from rich.table import Table
from rich.columns import Columns
# from rich.layout import Layout


banner = """
╔╗ ┌─┐┌┐ ┌┐ ┬  ┌─┐
╠╩╗├─┤├┴┐├┴┐│  ├┤ 
╚═╝┴ ┴└─┘└─┘┴─┘└─┘.py
Author: @Dreamkinn
"""

default_interface = "eth"

MDNS  = Table(title="MDNS")
DHCPv6 = Table(title="DHCPv6")
LLDP = Table(title="LLDP")
CDP  = Table(title="CDP")
BROWSER  = Table(title="BROWSER")
DNS  = Table(title="DNS")
# BROWSER : microsoft browser extension : Host name, main OS version
# under BROWSER : netbios : SOURCE NAME = HOST, DST NAME = domain, source IP : resolve

columns = Columns([MDNS,DHCPv6,BROWSER,LLDP,CDP])
# layout = Layout()

# layout.split_row(
#     Layout(MDNS),
#     Layout(DHCPv6),
#     Layout(LLDP)
# )


# TODO : last seen column (last time a packet was seen for a given query)
MDNS.add_column("Query name", style="green")
# MDNS.add_column("Last seen", style="green")

DHCPv6.add_column("CLient FQDN", style="red")
# MDNS.add_column("Last seen", style="green")

LLDP.add_column("System name", style="cyan")
# LLDP.add_column("Last seen", style="cyan")

CDP.add_column("Device ID", style="magenta")
# CDP.add_column("Last seen", style="magenta")

BROWSER.add_column("Server", style="blue")
# BROWSER.add_column("Last seen", style="green

DNS.add_column("Query name", style="blue")
# DNS.add_column("Last seen", style="green")

d = {}

# "lan" : <Table LAN>
# TODO : domain parsing and host aggregation
# tlds = {}
out = open("out_babble.txt",'w')

# TODO : ctrl C
# TODO sys.stdout.write

def dns_is_interesting(query):
    #return True # log all MDNS, including junk
    if query.lower().endswith("_tcp.local"):
        return False
    if query.lower().endswith("_udp.local"):
        return False
    if query.lower().endswith("ip6.arpa"):
        return False
    if query.lower().endswith("in-addr.arpa"):
        return False
    if query.lower().endswith("arpa.local"):
        return False
    return True

# TODO : Use for netbios|browser
def get_protocol_stack(packet):
    return list(map(lambda x: x._layer_name, packet.layers))

def handle_lldp(packet):
    if not d.get('lldp'):
        d['lldp'] = {"count":1}
    else:
        d['lldp']['count'] += 1
    LLDP.title = f"LLDP ({d['lldp']['count']})"

    if not d['lldp'].get(packet.lldp.tlv_system_name.lower()):
        if args["greppable"]:
            print(f"LLDP:{packet.lldp.tlv_system_name}")
            out.write(f"LLDP:{packet.lldp.tlv_system_name}\n")
            out.flush()
            d['lldp'][packet.lldp.tlv_system_name.lower()] = True
            return
        out.write(f"LLDP:{packet.lldp.tlv_system_name}\n")
        out.flush()
        LLDP.add_row(packet.lldp.tlv_system_name)
        d['lldp'][packet.lldp.tlv_system_name.lower()] = True

def handle_cdp(packet):
    if not d.get('cdp'):
        d['cdp'] = {"count":1}
    else:
        d['cdp']['count'] += 1
    CDP.title = f"CDP ({d['cdp']['count']})"

    if not d['cdp'].get(packet.cdp.deviceid.lower()):
        if args["greppable"]:
            print(f"CDP:{packet.cdp.deviceid}")
            out.write(f"CDP:{packet.cdp.deviceid}\n")
            out.flush()
            d['cdp'][packet.cdp.deviceid.lower()] = True
            return
        out.write(f"CDP:{packet.cdp.deviceid}\n")
        out.flush()
        CDP.add_row(packet.cdp.deviceid)
        d['cdp'][packet.cdp.deviceid.lower()] = True

def handle_dns(packet):
    if not d.get('dns'):
        d['dns'] = {"count":1}
    else:
        d['dns']['count'] += 1
    DNS.title = f"DNS ({d['dns']['count']})"

    if packet.dns.flags_response == '0':
        query = packet.dns.qry_name
    else:
        query = packet.dns.resp_name
    if not d['dns'].get(query.lower()):
        if args["greppable"]:
            print(f"DNS:{query}")
            out.write(f"DNS:{query}\n")
            out.flush()
            d['dns'][query.lower()] = True
            return
        out.write(f"DNS:{query}\n")
        out.flush()
        DNS.add_row(query)
        d['dns'][query.lower()] = True

def handle_dhcpv6(packet):
    if not d.get('dhcpv6'):
        d['dhcpv6'] = {"count":1}
    else:
        d['dhcpv6']['count'] += 1
    DHCPv6.title = f"DHCPv6 ({d['dhcpv6']['count']})"
    if not d['dhcpv6'].get(packet.dhcpv6.client_domain.lower()):
        if args["greppable"]:
            print(f"DHCPv6:{packet.dhcpv6.client_domain}")
            out.write(f"DHCPv6:{packet.dhcpv6.client_domain}\n")
            out.flush()
            d['dhcpv6'][packet.dhcpv6.client_domain.lower()] = True
            return
        out.write(f"DHCPv6:{packet.dhcpv6.client_domain}\n")
        out.flush()
        DHCPv6.add_row(packet.dhcpv6.client_domain)
        d['dhcpv6'][packet.dhcpv6.client_domain.lower()] = True


# TODO : handle several queries in one packet (apparently there is no answers field...)
# >>> cap[13].mdns.field_names
# >>> ['dns_id', 'dns_flags', 'dns_flags_response', 'dns_flags_opcode', 'dns_flags_authoritative', 'dns_flags_truncated', 'dns_flags_recdesired', 'dns_flags_recavail', 'dns_flags_z', 'dns_flags_authenticated', 'dns_flags_checkdisable', 'dns_flags_rcode', 'dns_count_queries', 'dns_count_answers', 'dns_count_auth_rr', 'dns_count_add_rr', '', 'dns_resp_name', 'dns_resp_type', 'dns_resp_class', 'dns_resp_cache_flush', 'dns_resp_ttl', 'dns_resp_len', 'dns_ptr_domain_name', 'dns_response_to', 'dns_time']
# -> only "dns_resp_name" and "dns_ptr_domain_name"
def handle_mdns(packet):
    if not d.get('mdns'):
        d['mdns'] = {"count":1}
    else:
        d['mdns']['count'] += 1
    MDNS.title = f"MDNS ({d['mdns']['count']})"
    if packet.mdns.dns_flags_response == '0':
        query = packet.mdns.dns_qry_name
    else:
        query = packet.mdns.dns_resp_name
    if not d['mdns'].get(query.lower()) and dns_is_interesting(query):
        if args["greppable"]:
            out.write(f"MDNS:{query}\n")
            out.flush()
            print(f"MDNS:{query}")
            d['mdns'][query.lower()] = True
            return
        out.write(f"MDNS:{query}\n")
        out.flush()
        MDNS.add_row(query)
        d['mdns'][query.lower()] = True

def handle_browser(packet):
    if not d.get('browser'):
        d['browser'] = {"count":1}
    else:
        d['browser']['count'] += 1
    BROWSER.title = f"BROWSER ({d['browser']['count']})"
    if not packet.browser.command == '0x09': # 'Get Backup List Request'
        if not d['browser'].get(packet.browser.server.lower()):
            if args["greppable"]:
                out.write(f"BROWSER:{packet.browser.server}:{packet.nbdgm.destination_name.replace('<1d>','')}\n")
                out.flush()
                print(f"BROWSER:{packet.browser.server}:{packet.nbdgm.destination_name.replace('<1d>','')}")
                d['browser'][packet.browser.server.lower()] = True
                return
            out.write(f"BROWSER:{packet.browser.server}:{packet.nbdgm.destination_name.replace('<1d>','')}\n")
            out.flush()
            # TODO check user agent before statuting on OS
            BROWSER.add_row(f'{packet.browser.server} {packet.nbdgm.destination_name.replace("<1d>","")} (Win {packet.browser.os_major}.{packet.browser.os_minor})')
            d['browser'][packet.browser.server.lower()] = True

 # netbios : cap[46].nbdgm.source_name
 # netbios : cap[46].nbdgm.destination_name
 # netbios : cap[46].browser.os_major
 # netbios : cap[46].browser.os_minor
 # browser : cap[46].browser.server

def loop_capture(cap):
    for packet in cap:
        if packet.layers[-1]._layer_name== 'lldp':
            handle_lldp(packet)
        elif packet.layers[-1]._layer_name== 'cdp':
            handle_cdp(packet)
        elif packet.layers[-1]._layer_name== 'mdns':
            handle_mdns(packet)
        elif packet.layers[-1]._layer_name== 'dhcpv6':
            handle_dhcpv6(packet)
        elif packet.layers[-1]._layer_name== 'dns' and args['dns']:
            handle_dns(packet)
        elif packet.layers[-1]._layer_name== 'browser':
            handle_browser(packet)


def wrapper_loop_capture(files):
    for file in files:
        cap = pyshark.FileCapture(file)
        loop_capture(cap)

if __name__ == "__main__":

    global current_live

    def proper_exit(*args):
        current_live.stop()
        input(f"\033[92m[+]Exiting and saving to out_babble.txt...\033[0m")
        # if a == 'y':
            # live.stop()
        out.close()
        exit(0) 
        # current_live.start()

    signal(SIGINT, proper_exit)


    parser = argparse.ArgumentParser(usage=SUPPRESS,formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""	
    ###	Babble - a passive discovery tool that analyzes network noise
        babble.py -i eth
        babble.py -f dump.pcapng
 
        # greppable
        babble.py -i eth -g
    		""")

    parser.add_argument('-f','--file',  type=str)
    parser.add_argument('-i','--interface',  type=str)
    parser.add_argument('-d','--dns', action=argparse.BooleanOptionalAction, default=False, help="Enable DNS logging, might pollute output")
    parser.add_argument('-g','--greppable', action=argparse.BooleanOptionalAction, default=False, help="Greppable output")

    # TODO : write data to file, so several captures can be merged
    # TODO : CIDR analysis
    # TODO : add progress bar
    parsed_args = parser.parse_args()
    args = vars(parsed_args)

    if not args["greppable"]:
        print(banner)

    if args["file"] and args["interface"]:
        print("Please specify either a file or an interface")
        exit(0)

    if args['dns']:
        columns.add_renderable(DNS)

    if args["file"]:
        if os.path.isdir(args["file"]):
            input_file = [os.path.abspath(args["file"]) + '/' + fl for fl in os.listdir(args["file"])]
        elif os.path.isfile(args["file"]):
            input_file = [args["file"]]
    
        input_file = list(map(lambda file: os.path.abspath(file), input_file))
        
        if args["greppable"]:
            wrapper_loop_capture(input_file)
            exit(0)

        with Live(columns, refresh_per_second=4, screen=True) as live:
            current_live = live
            live.console.print("Analyzing noise...\n")
            wrapper_loop_capture(input_file)

    elif args["interface"]:
        cap = pyshark.LiveCapture(interface=args["interface"])
        if args["greppable"]:
            loop_capture(cap)
            exit(0)
        with Live(columns, refresh_per_second=4, screen=True) as live:
            current_live = live
            live.console.print("Analyzing noise...\n")
            loop_capture(cap)
    else:
        print("No input specified, defaulting to interface eth")
        try:
            cap = pyshark.LiveCapture(interface=default_interface)
            if args["greppable"]:
                loop_capture(cap)
                exit(0)
            with Live(columns, refresh_per_second=4, screen=True) as live:
                current_live = live
                live.console.print("Analyzing noise...\n")
                loop_capture(cap)
        except:
            print("An error occured while trying to capture on interface eth")
            exit(0)
    
    proper_exit()
