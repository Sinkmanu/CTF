#!/usr/bin/env python

from scapy.all import *
import dpkt
import sys
import base64

# 2 first characters in the data section are chunks of a base64 encoded string.

pcapReader = dpkt.pcap.Reader(file("somepang.pcap", "rb"))
i = 0
b64d = ""
for ts, data in pcapReader:
    ether = dpkt.ethernet.Ethernet(data)
    ip = ether.data
    if isinstance(ip.data, dpkt.icmp.ICMP):
        icmp = ip.data
	cad = str(icmp.data)
	if (i%2==0):
		b64d = b64d + cad[len(cad)-24:len(cad)][0:2]
	i = i + 1

data = base64.decodestring(b64d)
# Looking the headers I know that it is a jpeg file

f = open('file.jpg', 'w')
f.write(data)
f.close()
print "[+] Result in: file.jpg"
