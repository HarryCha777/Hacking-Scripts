# Subdomains and Hidden Paths Crawler Via Wordlist

#!/use/bin/env python
import requests, optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="URL of site")
    parser.add_option("-w", "--wordlist", dest="wordlist", help="Path to wordlist")
    (options, arguments) = parser.parse_args()
    if not options.url:
        parser.error("[-] Please specify the URL of site. Use --help for more info.")
    if not options.wordlist:
        parser.error("[-] Please specify a path to wordlist. Use --help for more info.")
    return options

options = get_arguments()
protocol = options.url.split("//")[0]+"//"
target_url_without_protocol = options.url.split("//")[1]

with open(options.wordlist, "r") as wordlist_file:
    for line in wordlist_file:
        word = line.strip()
        test_url = protocol + word  + "." + target_url_without_protocol
        response = requests.get(test_url)
        if response:
            print("[+] Discovered subdomain --> " + test_url)
        test_url = protocol + target_url_without_protocol + "/" + word
        response = requests.get(test_url)
        if response:
            print("[+] Discovered path --> " + test_url)

'''
https://www.udemy.com/learn-python-and-ethical-hacking-from-scratch/learn/v4/t/lecture/10662276?start=0 (Discovering Subdomains)
https://www.udemy.com/learn-python-and-ethical-hacking-from-scratch/learn/v4/t/lecture/10662462?start=0 (Discovering Hidden Paths in Websites)
'''