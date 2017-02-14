#!/usr/bin/env python

"""
Challenge:
Found this packet capture. Pretty sure there's a flag in here. Can you find it!?

    dnscap.pcap 



Solution:
The traffic is DNS, we look the pattern of this DNS traffic and finally we found a magic header of PNG, so we look for the end magic header and generate the PNG file. The first time is not well generate because had repeated data, so we remove the duplicated and we got the flag.
"""

from scapy.all import *
import dpkt
import sys
import base64
import socket
import binascii


# PNG Magic numbers
png_magic_number_s = "89504e47"
png_magic_number_e = "49454e44ae426082"
data_sends = []
data_final = []

pcapReader = dpkt.pcap.Reader(file("dnscap.pcap", "rb"))
for ts, data in pcapReader:
        ether = dpkt.ethernet.Ethernet(data)
        ip = ether.data
        udp = ip.data
        ip_src = socket.inet_ntoa(ip.src)
        ip_dst = socket.inet_ntoa(ip.dst)
        dns = dpkt.dns.DNS(udp.data)
        # Get the traffic sent and remove unnecessary characters
        if ip_src == "192.168.43.91":
                data_sends.append(dns.qd[0].name[18:].replace(".skullseclabs.org","").replace(".",""))

# Remove repeated strings sent
for i in data_sends:
        if i not in data_final:
                data_final.append(i)


image_hex = ""
start = False
count = 0
end = False
while count < len(data_final) and not end:
        i = data_final[count]
        if start:
                image_hex = image_hex + i
        if i.find(png_magic_number_s) != -1:
                image_hex = image_hex + i[i.find(png_magic_number_s):]
                start = True
        if i.find(png_magic_number_e) != -1:
                image_hex = image_hex + i[:i.find(png_magic_number_s)+1]
                end = True
        count+=1

# Hex to binary
image = image_hex.decode("hex")

# Create the image with the flag
f = open('file.jpg', 'w')
f.write(image)
f.close()
print "[+] Result in: file.jpg"

