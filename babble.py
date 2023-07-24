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
from babbleutils.packet_handler import PacketHandler
# from rich.layout import Layout


banner = """
╔╗ ┌─┐┌┐ ┌┐ ┬  ┌─┐
╠╩╗├─┤├┴┐├┴┐│  ├┤ 
╚═╝┴ ┴└─┘└─┘┴─┘└─┘.py
Author: @Dreamkinn
"""

default_interface = "eth"
protocol_filter="lldp or browser or dns or mdns or netbios or dhcpv6 or cdp"

MDNS  = Table(title="MDNS")
DHCPv6 = Table(title="DHCPv6")
LLDP = Table(title="LLDP")
CDP  = Table(title="CDP")
BROWSER  = Table(title="BROWSER")
DNS  = Table(title="DNS")
TOTAL  = Table(title="TOTAL")
# BROWSER : microsoft browser extension : Host name, main OS version
# under BROWSER : netbios : SOURCE NAME = HOST, DST NAME = domain, source IP : resolve

columns = Columns([MDNS,DHCPv6,BROWSER,LLDP,CDP,TOTAL])
# layout = Layout()

# layout.split_row(
#     Layout(MDNS),
#     Layout(DHCPv6),
#     Layout(LLDP)
# )

# TODO : tld proposal (.local, .lan, .corp, .group, .intranet, .com)

# TODO : last seen column (last time a packet was seen for a given query)
MDNS.add_column("Query name", style="green")
# MDNS.add_column("Last seen", style="green")

DHCPv6.add_column("Client FQDN", style="red")
# MDNS.add_column("Last seen", style="green")

LLDP.add_column("System name", style="cyan")
# LLDP.add_column("Last seen", style="cyan")

CDP.add_column("Device ID", style="magenta")
# CDP.add_column("Last seen", style="magenta")

BROWSER.add_column("Server", style="blue")
# BROWSER.add_column("Last seen", style="green

DNS.add_column("Query name", style="blue")
# DNS.add_column("Last seen", style="green")

TOTAL.add_column("TOTAL",style="blue")

d = {}

# "lan" : <Table LAN>
# TODO : domain parsing and host aggregation
# tlds = {}
if not os.path.isfile("out_babble.txt"):
    out = open("out_babble.txt",'w')
else:
    from datetime import datetime
    date_time_str = datetime.now().strftime("%Y-%m-%d_%H:%M")
    out = open(f"out_babble_{date_time_str}.txt",'w')
    

# TODO : ctrl C
# TODO sys.stdout.write

 # netbios : cap[46].nbdgm.source_name
 # netbios : cap[46].nbdgm.destination_name
 # netbios : cap[46].browser.os_major
 # netbios : cap[46].browser.os_minor
 # browser : cap[46].browser.server

def loop_capture(cap, debug=False):
    ph = PacketHandler(args, d, LLDP, CDP, DNS, MDNS, BROWSER,DHCPv6, out, debug=debug)
    parsed = 0
    for packet in cap:
        parsed +=1
        TOTAL.title = f"TOTAL {parsed}"
        if packet.layers[-1]._layer_name== 'lldp':
            ph.handle_lldp(packet)
        elif packet.layers[-1]._layer_name== 'cdp':
            ph.handle_cdp(packet)
        elif packet.layers[-1]._layer_name== 'mdns':
            ph.handle_mdns(packet)
        elif packet.layers[-1]._layer_name== 'dhcpv6':
            ph.handle_dhcpv6(packet)
        elif packet.layers[-1]._layer_name== 'dns' and args['dns']:
            ph.handle_dns(packet)
        elif packet.layers[-1]._layer_name== 'browser':
            ph.handle_browser(packet)
        # elif packet.layers[-1]._layer_name== 'netbios':
        #     ph.handle_netbios(packet)

def wrapper_loop_capture(files, debug):
    for file in files:
        cap = pyshark.FileCapture(file, display_filter=protocol_filter)
        loop_capture(cap, debug)

if __name__ == "__main__":

    global current_live

    def proper_exit(*args):
        current_live.stop()
        print(f"\033[92m[+]Exiting and saving to {out.name}...\033[0m")
        # if a == 'y':
            # live.stop()
        out.close()
        exit(0) 
        # current_live.start()

    signal(SIGINT, proper_exit)


    parser = argparse.ArgumentParser(usage=SUPPRESS,formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""	
    ###	Babble - a passive discovery tool that analyzes network noise
        babble.py -i eth0
        babble.py -f dump.pcapng
 
        # greppable
        babble.py -i eth -g
    		""")

    parser.add_argument('-f','--file',  type=str)
    parser.add_argument('-i','--interface',  type=str)
    parser.add_argument('-g','--greppable', action="store_true", help="Greppable output")
    parser.add_argument('-s','--fullscreen', action="store_true", help="Make fullscreen")
    parser.add_argument('-d','--dns', action="store_true", help="Enable DNS logging, might pollute output")
    parser.add_argument('-j','--junk', action="store_true", help="Enable Junk MDNS logging, might pollute output")
    parser.add_argument('-D','--debug', action="store_true", help="Enable debug mode")
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
            wrapper_loop_capture(input_file, args.get("debug"))
            exit(0)

        with Live(columns, refresh_per_second=4, screen=args["fullscreen"]) as live:
        # with Live(columns, refresh_per_second=4) as live:
            current_live = live
            live.console.print("Analyzing noise...\n")
            wrapper_loop_capture(input_file, args.get("debug"))

    elif args["interface"]:
        # TODO : use BPF filters = much faster
        cap = pyshark.LiveCapture(  interface=args["interface"], 
                                    tshark_path="/usr/bin/tshark",
                                    display_filter=protocol_filter)
        if args["greppable"]:
            loop_capture(cap)
            exit(0)
        with Live(columns, refresh_per_second=4, screen=args["fullscreen"]) as live:
        # with Live(columns, refresh_per_second=4) as live:
            current_live = live
            live.console.print("Analyzing noise...\n")
            loop_capture(cap)
    else:
        print("No input specified, defaulting to interface eth")
        try:
            cap = pyshark.LiveCapture(  interface=default_interface,
                                        tshark_path="/usr/bin/tshark",
                                        display_filter=protocol_filter)
            if args["greppable"]:
                loop_capture(cap)
                exit(0)
            with Live(columns, refresh_per_second=4, screen=args["fullscreen"]) as live:
            # with Live(columns, refresh_per_second=4) as live:
                current_live = live
                live.console.print("Analyzing noise...\n")
                loop_capture(cap)
        except:
            print("An error occured while trying to capture on interface eth")
            exit(0)

    proper_exit()
