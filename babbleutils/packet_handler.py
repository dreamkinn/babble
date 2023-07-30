def get_protocol_stack(packet):
    return list(map(lambda x: x._layer_name, packet.layers))

def print_error(msg):
    print(f"\033[91m[!] {msg}\033[0m")

def print_info(msg):
    print(f"\033[94m[*] {msg}\033[0m")

def lookup_windows(nt):
    win = {
        "5.0":"(Windows 2000)",
        "5.1":"(Windows XP)",
        "5.2":"(Windows Server 2003)",
        "6.0":"(Windows Server 2008)",
        "6.1":"(Linux|Windows 7|Windows 2008R2)",
        "6.2":"(Windows 2012)",
        "6.3":"(Windows 2012R2)",
        "10":"(Windows 10|Windows Server 2016+)"
    }
    if win.get(nt):
        return win[nt]
    return ""

class PacketHandler:
    def __init__(self, args, d, LLDP, CDP, DNS, MDNS, BROWSER,DHCPv6, output, debug=False):
        self.d = d
        self.args = args
        self.out = output

        self.LLDP = LLDP
        self.CDP = CDP
        self.DNS = DNS
        self.MDNS = MDNS
        self.BROWSER = BROWSER
        self.DHCPv6 = DHCPv6
        self.debug = debug

    def handle_lldp(self, packet):
        if not self.d.get('lldp'):
            self.d['lldp'] = {"count":1}
        else:
            self.d['lldp']['count'] += 1
        self.LLDP.title = f"LLDP ({self.d['lldp']['count']})"

        try:
            if self.debug:
                self.print_packet("lldp", packet, packet.lldp, packet.lldp.tlv_type)

            if not self.d['lldp'].get(packet.lldp.tlv_system_name.lower()):
                vlan_name = ""
                if "ieee_802_1_vlan_name" in packet.lldp.field_names:
                    vlan_name = packet.lldp.ieee_802_1_vlan_name  
                if self.args["greppable"]:
                    print(f"LLDP:{packet.lldp.tlv_system_name} : {vlan_name}")
                    self.out.write(f"LLDP:{packet.lldp.tlv_system_name}:{vlan_name}\n")
                    self.out.flush()
                    self.d['lldp'][packet.lldp.tlv_system_name.lower()] = True
                    return
                self.out.write(f"LLDP:{packet.lldp.tlv_system_name}:{vlan_name}\n")
                self.out.flush()
                self.LLDP.add_row(f"{packet.lldp.tlv_system_name} : {vlan_name}")
                self.d['lldp'][packet.lldp.tlv_system_name.lower()] = True
        except:
            if self.debug:
                print_error("Error in handle_lldp")
                self.print_packet("lldp", packet, packet.lldp, packet.lldp.tlv_system_name, print=print_error)

    def handle_cdp(self, packet):
        if not self.d.get('cdp'):
            self.d['cdp'] = {"count":1}
        else:
            self.d['cdp']['count'] += 1
        self.CDP.title = f"CDP ({self.d['cdp']['count']})"

        try:
            if self.debug:
                self.print_packet("cdp", packet, packet.cdp, packet.cdp.deviceid)
            if not self.d['cdp'].get(packet.cdp.deviceid.lower()):

                ip = ""
                if "nrgyz_ip_address" in packet.cdp.field_names:
                    ip = packet.cdp.nrgyz_ip_address 
                if self.args["greppable"]:
                    print(f"CDP:{packet.cdp.deviceid} : {ip}")
                    self.out.write(f"CDP:{packet.cdp.deviceid} : {ip}\n")
                    self.out.flush()
                    self.d['cdp'][packet.cdp.deviceid.lower()] = True
                    return
                self.out.write(f"CDP:{packet.cdp.deviceid} : {ip}\n")
                self.out.flush()
                self.CDP.add_row(f"{packet.cdp.deviceid} : {ip}")
                self.d['cdp'][packet.cdp.deviceid.lower()] = True
        except:
            if self.debug:
                print_error("Error in handle_cdp")
                self.print_packet("cdp", packet, packet.cdp, packet.cdp.deviceid, print=print_error, force=True)

    def handle_dns(self, packet):
        if not self.d.get('dns'):
            self.d['dns'] = {"count":1}
        else:
            self.d['dns']['count'] += 1
        self.DNS.title = f"DNS ({self.d['dns']['count']})"

        try:
            if packet.dns.flags_response == '0':
                query = packet.dns.qry_name
            else:
                query = packet.dns.resp_name
            if not self.d['dns'].get(query.lower()):
                if self.args["greppable"]:
                    print(f"DNS:{query}")
                    self.out.write(f"DNS:{query}\n")
                    self.out.flush()
                    self.d['dns'][query.lower()] = True
                    return
                self.out.write(f"DNS:{query}\n")
                self.out.flush()
                self.DNS.add_row(query)
                self.d['dns'][query.lower()] = True
        except:
            if self.debug:
                print_error("Error in handle_dns")
                print(get_protocol_stack(packet))

    def handle_dhcpv6(self, packet):
        if not self.d.get('dhcpv6'):
            self.d['dhcpv6'] = {"count":1}
        else:
            self.d['dhcpv6']['count'] += 1
        self.DHCPv6.title = f"DHCPv6 ({self.d['dhcpv6']['count']})"
        
        if self.debug:
            self.print_packet("dhcpv6", packet, packet.dhcpv6, packet.dhcpv6.option_type)

        try:
            if not self.d['dhcpv6'].get(packet.dhcpv6.client_domain.lower()):
                if self.args["greppable"]:
                    print(f"DHCPv6:{packet.dhcpv6.client_domain}")
                    self.out.write(f"DHCPv6:{packet.dhcpv6.client_domain}\n")
                    self.out.flush()
                    self.d['dhcpv6'][packet.dhcpv6.client_domain.lower()] = True
                    return
                self.out.write(f"DHCPv6:{packet.dhcpv6.client_domain}\n")
                self.out.flush()
                self.DHCPv6.add_row(packet.dhcpv6.client_domain)
                self.d['dhcpv6'][packet.dhcpv6.client_domain.lower()] = True
        except:
            if self.debug:
                print_error("Error in handle_dhcpv6")
                self.print_packet("dhcpv6", packet, packet.dhcpv6, packet.dhcpv6.client_domain, print=print_error)


    # TODO : handle several queries in one packet (apparently there is no answers field...)
    # >>> cap[13].mdns.field_names
    # >>> ['dns_id', 'dns_flags', 'dns_flags_response', 'dns_flags_opcode', 'dns_flags_authoritative', 'dns_flags_truncated', 'dns_flags_recdesired', 'dns_flags_recavail', 'dns_flags_z', 'dns_flags_authenticated', 'dns_flags_checkdisable', 'dns_flags_rcode', 'dns_count_queries', 'dns_count_answers', 'dns_count_auth_rr', 'dns_count_add_rr', '', 'dns_resp_name', 'dns_resp_type', 'dns_resp_class', 'dns_resp_cache_flush', 'dns_resp_ttl', 'dns_resp_len', 'dns_ptr_domain_name', 'dns_response_to', 'dns_time']
    # -> only "dns_resp_name" and "dns_ptr_domain_name"
    def handle_mdns(self, packet):
        if not self.d.get('mdns'):
            self.d['mdns'] = {"count":1}
        else:
            self.d['mdns']['count'] += 1
        self.MDNS.title = f"MDNS ({self.d['mdns']['count']})"

        # try:
        queries = []
        if 'dns_resp_name' in packet.mdns.field_names:
            queries.append(packet.mdns.dns_resp_name)
        if 'dns_ptr_domain_name' in packet.mdns.field_names:
            queries.append(packet.mdns.dns_ptr_domain_name)
        if 'dns_qry_name' in packet.mdns.field_names:
            queries.append(packet.mdns.dns_qry_name)
        if 'dns_srv_target' in packet.mdns.field_names:
            target = packet.mdns.dns_srv_target
            if 'dns_srv_port' in packet.mdns.field_names:
                target += f":{packet.mdns.dns_srv_port}"
            if 'dns_hinfo_os' in packet.mdns.field_names:
                target += f" ({packet.mdns.dns_hinfo_os})"
            queries.append(target)
        
        info = []
        if 'dns_txt' in packet.mdns.field_names:
            info.append(packet.mdns.dns_txt)
        if 'dns_hinfo_os' in  packet.mdns.field_names:
            info.append(packet.mdns.dns_hinfo_os)
            
        if self.debug:
            self.print_packet("mdns", packet, packet.mdns, packet.mdns.dns_qry_type)
        for query in queries:
            if not self.d['mdns'].get(query.lower()) and self.dns_is_interesting(query):
                if self.args["greppable"]:
                    self.out.write(f"MDNS:{query}\n")
                    self.out.flush()
                    print(f"MDNS:{query}")
                    self.d['mdns'][query.lower()] = True
                    return
                self.out.write(f"MDNS:{query}\n")
                self.out.flush()
                self.MDNS.add_row(query)
                self.d['mdns'][query.lower()] = True
        # except:
        #     if self.debug:
        #         print_error("Error in handle_mdns")
        #         if packet.mdns.dns_flags_response == '0':
        #             self.print_packet("mdns", packet, packet.mdns, packet.mdns.dns_qry_type, print=print_error, force=True)
        #         else:
        #             self.print_packet("mdns", packet, packet.mdns, packet.mdns.dns_resp_type, print=print_error, force=True)

# doc here : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-brws/0e74d70e-dcf7-422e-8285-e2e193f363d9
    def handle_browser(self, packet):
        if not self.d.get('browser'):
            self.d['browser'] = {"count":1}
        else:
            self.d['browser']['count'] += 1
        self.BROWSER.title = f"BROWSER ({self.d['browser']['count']})"

        # not interesting
        if packet.browser.command == "0x08" or packet.browser.command == "0x09":
            return

        try:
            # if not packet.browser.command == '0x09': # 'Get Backup List Request'
            if self.debug:
                self.print_packet("browser", packet, packet.browser, packet.browser.command)
            

            if packet.browser.command == "0x02":
                identifier = packet.browser.response_computer_name
            elif packet.browser.command == "0x0a":
                identifier = packet.browser.backup_server
            elif packet.browser.command == "0x0b":
                identifier = packet.browser.browser_to_promote
            else:
                identifier = packet.browser.server

            if not self.d['browser'].get(identifier.lower()):
                stack = get_protocol_stack(packet)
 
                nb_name = ""
                dst_name = ""
                if "netbios" in stack:
                    # TODO : sender_name is inaccessible, only nb name
                    nb_name = packet.netbios.nb_name.replace('<01>','').replace('<02>','').replace('<1d>','').replace('<1e>','')
                if "nbdgm" in stack:
                    dst_name = packet.nbdgm.destination_name.replace('<01>','').replace('<02>','').replace('<1d>','').replace('<1e>','')

                mb_server = ""
                comment = ""
                if packet.browser.command == "0x01":
                    if packet.browser.comment != "00":
                        comment = packet.browser.comment
                elif packet.browser.command == "0x0c":
                    mb_server = packet.browser.mb_server
                elif packet.browser.command == "0x0f":
                    if packet.browser.comment != "00":
                        comment = packet.browser.comment

                windows=""
                if "windows_version" in packet.browser.field_names:
                    if len(packet.browser.windows_version) != 4: # e.g. 0409
                        windows = f"({packet.browser.windows_version.replace(' or ','|')})"
                else:
                    windows = lookup_windows(f"{packet.browser.os_major}.{packet.browser.os_minor}")
                out_arr = [f"{dst_name}\{identifier}", nb_name, windows, mb_server, comment]
                # join with : or space depending on greppable
                out_str = ":".join(out_arr) if self.args["greppable"] else " ".join(out_arr)

                if self.args["greppable"]:
                    self.out.write(f"BROWSER:{out_str}\n")
                    self.out.flush()
                    print(f"BROWSER:{out_str}")
                    self.d['browser'][identifier.lower()] = True
                    return
                self.out.write(f"BROWSER:{out_str}\n")
                self.out.flush()
                # TODO check user agent before statuting on OS
                self.BROWSER.add_row(out_str)
                self.d['browser'][identifier.lower()] = True
        except:
            if self.debug:
                print_error("Error in handle_browser")
                print_error(f"Stack : {get_protocol_stack(packet)}")
                self.print_packet("browser", packet, packet.browser, packet.browser.command, print=print_error, force=True)

    # def handle_netbios(self,packet):
    #     if not self.d.get('browser'):
    #         self.d['browser'] = {"count":1}
    #     else:
    #         self.d['browser']['count'] += 1
    #     self.BROWSER.title = f"BROWSER ({self.d['browser']['count']})"
    #     try:
    #         if packet.netbios.command == '0x0a': # Name Query
    #             if not self.d['browser'].get(packet.netbios.nb_name.lower()):
    #                 if self.args["greppable"]:
    #                     self.out.write(f"BROWSER:{packet.netbios.nb_name}\n")
    #                     self.out.flush()
    #                     print(f"BROWSER:{packet.netbios.nb_name}")
    #                     self.d['browser'][packet.netbios.nb_name.lower()] = True
    #                     return
    #                 self.out.write(f"BROWSER:{packet.netbios.nb_name}\n")
    #                 self.out.flush()
    #                 self.BROWSER.add_row(packet.netbios.nb_name)
    #                 self.d['browser'][packet.netbios.nb_name.lower()] = True
    #     except:
    #         if self.debug:
    #             print_error("Error in handle_netbios")
    #             print(get_protocol_stack(packet))

    def dns_is_interesting(self, query):
        if self.args["junk"]:
            return True # log all MDNS, including junk
            
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

    def print_packet(self,protocolstring, packet, protocol, identifier,print=print_info, force=False):
        # print_error(packet)
        if not self.d.get(f"{protocolstring}{identifier}") or force:
            print(f"Stack : {get_protocol_stack(packet)}")
            print(protocol.field_names)
            for i in protocol.field_names:
                print(f'{i} : {getattr(protocol,i)}')
            self.d[f"{protocolstring}{identifier}"] = protocol.field_names
        # else:
        #     print(f"Packet type already pretty printed. Skipping...")

