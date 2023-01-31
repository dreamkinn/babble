
class PacketHandler:
    def __init__(self, args, d, LLDP, CDP, DNS, MDNS, BROWSER,DHCPv6, output):
        self.d = d
        self.args = args
        self.out = output

        self.LLDP = LLDP
        self.CDP = CDP
        self.DNS = DNS
        self.MDNS = MDNS
        self.BROWSER = BROWSER
        self.DHCPv6 = DHCPv6

    def handle_lldp(self, packet):
        if not self.d.get('lldp'):
            self.d['lldp'] = {"count":1}
        else:
            self.d['lldp']['count'] += 1
        self.LLDP.title = f"LLDP ({self.d['lldp']['count']})"

        try:
            if not self.d['lldp'].get(packet.lldp.tlv_system_name.lower()):
                if self.args["greppable"]:
                    print(f"LLDP:{packet.lldp.tlv_system_name}")
                    self.out.write(f"LLDP:{packet.lldp.tlv_system_name}\n")
                    self.out.flush()
                    self.d['lldp'][packet.lldp.tlv_system_name.lower()] = True
                    return
                self.out.write(f"LLDP:{packet.lldp.tlv_system_name}\n")
                self.out.flush()
                self.LLDP.add_row(packet.lldp.tlv_system_name)
                self.d['lldp'][packet.lldp.tlv_system_name.lower()] = True
        except:
            print("Error in handle_lldp")
            print(self.get_protocol_stack(packet))

    def handle_cdp(self, packet):
        if not self.d.get('cdp'):
            self.d['cdp'] = {"count":1}
        else:
            self.d['cdp']['count'] += 1
        self.CDP.title = f"CDP ({self.d['cdp']['count']})"

        try:
            if not self.d['cdp'].get(packet.cdp.deviceid.lower()):
                if self.args["greppable"]:
                    print(f"CDP:{packet.cdp.deviceid}")
                    self.out.write(f"CDP:{packet.cdp.deviceid}\n")
                    self.out.flush()
                    self.d['cdp'][packet.cdp.deviceid.lower()] = True
                    return
                self.out.write(f"CDP:{packet.cdp.deviceid}\n")
                self.out.flush()
                self.CDP.add_row(packet.cdp.deviceid)
                self.d['cdp'][packet.cdp.deviceid.lower()] = True
        except:
            print("Error in handle_cdp")
            print(self.get_protocol_stack(packet))

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
            print("Error in handle_dns")
            print(self.get_protocol_stack(packet))

    def handle_dhcpv6(self, packet):
        if not self.d.get('dhcpv6'):
            self.d['dhcpv6'] = {"count":1}
        else:
            self.d['dhcpv6']['count'] += 1
        self.DHCPv6.title = f"DHCPv6 ({self.d['dhcpv6']['count']})"

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
            print("Error in handle_dhcpv6")
            print(self.get_protocol_stack(packet))


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

        try:
            if packet.mdns.dns_flags_response == '0':
                query = packet.mdns.dns_qry_name
            else:
                query = packet.mdns.dns_resp_name
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
        except:
            print("Error in handle_mdns")
            print(self.get_protocol_stack(packet))

    def handle_browser(self, packet):
        if not self.d.get('browser'):
            self.d['browser'] = {"count":1}
        else:
            self.d['browser']['count'] += 1
        self.BROWSER.title = f"BROWSER ({self.d['browser']['count']})"

        try:
            if not packet.browser.command == '0x09': # 'Get Backup List Request'
                stack = self.get_protocol_stack(packet)
                nb_name = ""
                dst_name = ""
                if "netbios" in stack:
                    # TODO : sender_name is inaccessible, only nb name
                    nb_name = packet.netbios.nb_name.replace('<01>','').replace('<02>','')
                if "nbdgm" in stack:
                    dst_name = packet.nbdgm.destination_name.replace('<1d>','')

                if not self.d['browser'].get(packet.browser.server.lower()):
                    if self.args["greppable"]:
                        self.out.write(f"BROWSER:{packet.browser.server}:{dst_name}:{nb_name}\n")
                        self.out.flush()
                        print(f"BROWSER:{packet.browser.server}:{dst_name}:{nb_name}")
                        self.d['browser'][packet.browser.server.lower()] = True
                        return
                    self.out.write(f"BROWSER:{packet.browser.server}:{dst_name}:{nb_name}\n")
                    self.out.flush()
                    # TODO check user agent before statuting on OS
                    self.BROWSER.add_row(f'{packet.browser.server} {dst_name} {nb_name} (Win {packet.browser.os_major}.{packet.browser.os_minor})')
                    self.d['browser'][packet.browser.server.lower()] = True
        except:
            print("Error in handle_browser")
            print(self.get_protocol_stack(packet))
    
    def handle_netbios(self,packet):
        if not self.d.get('browser'):
            self.d['browser'] = {"count":1}
        else:
            self.d['browser']['count'] += 1
        self.BROWSER.title = f"BROWSER ({self.d['browser']['count']})"
        try:
            if packet.netbios.command == '0x0a': # Name Query
                if not self.d['browser'].get(packet.netbios.nb_name.lower()):
                    if self.args["greppable"]:
                        self.out.write(f"BROWSER:{packet.netbios.nb_name}\n")
                        self.out.flush()
                        print(f"BROWSER:{packet.netbios.nb_name}")
                        self.d['browser'][packet.netbios.nb_name.lower()] = True
                        return
                    self.out.write(f"BROWSER:{packet.netbios.nb_name}\n")
                    self.out.flush()
                    self.BROWSER.add_row(packet.netbios.nb_name)
                    self.d['browser'][packet.netbios.nb_name.lower()] = True
        except:
            print("Error in handle_netbios")
            print(self.get_protocol_stack(packet))

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

    def get_protocol_stack(self, packet):
        return list(map(lambda x: x._layer_name, packet.layers))