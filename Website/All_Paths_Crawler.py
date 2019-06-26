# All Paths Crawler

#!/use/bin/env python
import requests, urlparse, optparse, re

original_url = ""
checked_links = []

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="URL of site")
    (options, arguments) = parser.parse_args()
    if not options.url:
        parser.error("[-] Please specify the URL of site. Use --help for more info.")
    return options

def extract_links_from(url):
    response = requests.get(url)
    return re.findall('(?:href=")(.*?)"', response.content)

def crawl(current_url):
    href_links = extract_links_from(current_url)
    for link in href_links:
        link = urlparse.urljoin(current_url, link)
        if "#" in link:
            link = link.split("#")[0]
        if original_url in link and link not in checked_links:
            checked_links.append(link)
            print(link)
            crawl(link)

options = get_arguments()
original_url = options.url
crawl(original_url)

'''
https://www.udemy.com/learn-python-and-ethical-hacking-from-scratch/learn/v4/t/lecture/10665870?start=0 (Recursively Discovering All Paths On a Target Website)
'''