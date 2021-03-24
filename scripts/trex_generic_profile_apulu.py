from trex.astf.api import *
import os
import sys
import random
import ipaddress

class Prof1():
    def __init__(self):
        self.udp_port = 52
        self.http_port = 80
        self.tcp_port = 51

    def create_profile(self, client_ip, server_ip, cps, pcap_file):

        pcap_file = os.path.join(os.path.dirname(__file__), "pcap", pcap_file)

        # Client program taken from client side of given file
        client_prog = ASTFProgram(file=pcap_file, side="c")

        # Server program taken from server side of given file
        server_prog = ASTFProgram(file=pcap_file, side="s")

        port_count = 1
        template_list = []

        # ip generator
        ip_gen_c1 = ASTFIPGenDist(ip_range=[client_ip, "2.1.0.165"], distribution="seq")
        ip_gen_s1 = ASTFIPGenDist(ip_range=[server_ip, "2.1.0.65"], distribution="seq")
        ip_gen1 = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="0.0.0.1"), dist_client=ip_gen_c1, dist_server=ip_gen_s1)
        

	# template generator
        i = 0
        while i < port_count :
            port_gen = 80 + i #trex doesnt like duplicate server ports
            temp_ci = ASTFTCPClientTemplate(program=client_prog, ip_gen=ip_gen1,cps=(cps/port_count),port=port_gen)
            temp_si = ASTFTCPServerTemplate(program=server_prog, assoc=ASTFAssociationRule(port=port_gen))
            template_port = ASTFTemplate(client_template=temp_ci, server_template=temp_si)
            template_list.append(template_port)
            i = i + 1
            
       # profile
        profile = ASTFProfile(default_ip_gen=ip_gen1,templates = template_list)
        return profile

    def get_profile(self, **kwargs):
        client_ip = kwargs.get("client_ip", "2.1.0.102")
        server_ip = kwargs.get("server_ip", "2.1.0.2")
        cps =       kwargs.get("cps", 1000)
        pcap_file = kwargs.get("pcap_file", "http_gzip.cap")
        return self.create_profile(str(client_ip), str(server_ip), cps, pcap_file)

def register():
    return Prof1()
