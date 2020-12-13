#!/usr/bin/env python3
import glob
import os
import socket
import tarfile
import urllib
from io import BytesIO
from subprocess import check_output
from zipfile import ZipFile

import requests
import xmltodict
from termcolor import colored


def get_arguments():
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('--target',
                        dest='target',
                        required=True,
                        type=str,
                        help='Specify the target (an email address, a domain name or an URL) '
                             'to find cross-references in the phishing databases')
    options = parser.parse_args()
    return options


class PhishRadare:
    def __init__(self):
        pass

    def check_openphish_feed(self, domain):
        print('[*] Scraping Openphish feed')
        openphish_feed_url = 'https://openphish.com/feed.txt'

        phish = set()
        resp = requests.get(openphish_feed_url)
        if resp.ok:
            feed = [line.strip() for line in resp.text.split(os.linesep) if line.strip()]
            if feed:
                for line in feed:
                    if domain.lower() in line.lower():
                        phish.add(line.replace(domain, colored(domain, 'red')))
            else:
                print('[-] Openphish feed is empty')
        else:
            print('[-] Openphish feed rejected our request')
        if phish:
            print('-' * 50)
            print('[!] OPENPHISH - DOMAIN FOUND')
            for line in phish:
                print(line)
            print('-' * 50)
        return phish

    def check_phishstats(self, domain):
        column = 'url'
        compare = 'like'
        search = f"~{domain}~"
        phish = set()
        print('[*] Calling PhishStats API')
        resp = requests.get(
            'https://phishstats.info:2096/api/phishing',
            params={'_where': '(' + column + ',' + compare + ',' + search + ')', '_sort': '-id'},
            headers={'User-Agent': 'github-network-api'}
        )
        if resp.ok:
            for entry in resp.json():
                phish.add(entry['url'].replace(domain, colored(domain, 'red')))
        else:
            print('[-] PhishStats rejected our request')
        if phish:
            print('-' * 50)
            print('[!] PHISHSTATS - DOMAIN FOUND')
            for line in phish:
                print(line)
            print('-' * 50)
        return phish

    def check_mitchellkrogza_database(self, domain):
        print('[*] Checking Mitchkrongza database')
        phish_domains_url = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/ALL-phishing-domains.tar.gz'
        phish_links_url = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/ALL-phishing-links.tar.gz'

        domains_resp = requests.get(phish_domains_url)
        links_resp = requests.get(phish_links_url)
        domains_file_name = 'phish-domains.tar.gz'
        with open(domains_file_name, 'wb') as f:
            f.write(domains_resp.content)
        with tarfile.open(domains_file_name, 'r:gz') as tar:
            tar.extractall()
        links_file_name = 'phish-links.tar.gz'
        with open(links_file_name, 'wb') as f:
            f.write(links_resp.content)
        with tarfile.open(links_file_name, 'r:gz') as tar:
            tar.extractall()

        files = glob.glob('./home/travis/build/mitchellkrogza/Phishing.Database/*')

        content = set()
        for file in files:
            with open(file, 'r') as f:
                for line in [l.strip() for l in f.readlines()]:
                    content.add(line)

        phish = set()
        for line in content:
            if domain.lower() in line.lower():
                phish.add(line.replace(domain, colored(domain, 'red')))
        if phish:
            print('-' * 50)
            print('[!] MITCHKRONGZA DATABASE - DOMAIN FOUND')
            for line in phish:
                print(line)
            print('-' * 50)
        return phish

    def check_phishtank(self, domain):
        print('[*] Checking the PhishTank database')

        phish = set()
        for scheme in ['http://', 'https://']:
            url = f"{scheme}{domain}"
            resp = requests.post('http://phishtank.org/checkurl/',
                                 params={'url': url},
                                 # data=f'url={url}'
                                 )
            if resp.ok:
                phishtank_data = xmltodict.parse(resp.text)
                if 'response' in phishtank_data:
                    phishtank_data_response = phishtank_data['response']
                    if 'results' in phishtank_data_response:
                        results = phishtank_data_response['results']
                        for result in results.values():
                            url = result['url']
                            in_database = result['in_database']
                            if in_database == 'false':
                                continue
                            else:
                                phish.add(url)
        if phish:
            print('-' * 50)
            print('[!] PHISHTANK - DOMAIN FOUND')
            for line in phish:
                print(line.replace(domain, colored(domain, 'red')))
            print('-' * 50)
        return phish

    def check_abuseipdb(self, domain):
        print('[*] Checking the AbuseIP database')
        phish = set()
        try:
            ip_address = socket.gethostbyname(domain)
            url = f'https://www.abuseipdb.com/check/{ip_address}'
            resp = requests.get(url)
            if resp.ok:
                if 'has not been reported' in resp.text:
                    return
                else:
                    phish.add(url)
        except socket.gaierror as e:
            print(e)
        if phish:
            print('-' * 50)
            print("[!] ABUSEIPDB - IP ADDRESS FOUND")
            for line in phish:
                print(line.replace(domain, colored(domain, 'red')))
            print('-' * 50)
        return phish

    def check_whois(self, domain):
        print('[*] Searching WHOIS database for the general information')
        try:
            output = check_output(['whois', domain]).decode('utf-8')
            text = output.replace(domain, colored(domain, 'red')).replace(domain, colored(domain.upper(), 'red'))
            print(text)
            return text
        except Exception as e:
            print(e)

    def check_alexa_top1m(self, domain):
        dataset_url = 'https://s3.amazonaws.com/alexa-static/top-1m.csv.zip'

        print(f'[*] Checking the Alexa TOP-1 Million phishing dataset')
        resp = requests.get(dataset_url)
        phish = set()
        if resp.ok:
            zipfile = ZipFile(BytesIO(resp.content))
            for name in zipfile.namelist():
                for line in [l.decode('utf-8').split(',')[1].strip() for l in zipfile.open(name).readlines()]:
                    if domain.lower() in line.lower():
                        phish.add(line)
        else:
            print("[-] Alexa top 1M rejected our request")
        if phish:
            print('-' * 50)
            print("[!] ALEXA TOP-1 MILLION - DOMAIN FOUND")
            for line in phish:
                print(line.replace(domain, colored(domain, 'red')))
            print('-' * 50)
        return phish

    def check_binary_defense(self, domain):
        print(f'[*] Checking Binary Defense Threat Intelligence Feed')

        banlist_url = 'https://www.binarydefense.com/banlist.txt'

        phish = set()
        try:
            ip_address = socket.gethostbyname(domain)
            resp = requests.get(banlist_url)
            if resp.ok:
                if ip_address not in resp.text:
                    return
                else:
                    phish.add(f"{domain} - {ip_address}")
        except socket.gaierror as e:
            print(e)
        if phish:
            print('-' * 50)
            print("[!] BINARY DEFENSE - DOMAIN FOUND")
            for line in phish:
                print(line.replace(domain, colored(domain, 'red')))
            print('-' * 50)
        return phish

    def check_ci_army_list(self, domain):
        dataset_url = 'http://cinsscore.com/list/ci-badguys.txt'

        print('[*] Checking the CI Army dataset')
        phish = set()
        try:
            ip_address = socket.gethostbyname(domain)
            resp = requests.get(dataset_url)
            if resp.ok:
                if ip_address not in resp.text:
                    return
                else:
                    phish.add(f'{domain} - {ip_address}')
        except socket.gaierror as e:
            print(e)
        if phish:
            print('-' * 50)
            print("[!] CI ARMY LIST - IP ADDRESS FOUND")
            for line in phish:
                print(line.replace(domain, colored(domain, 'red')))
            print('-' * 50)
        return phish

    def check_disposable_email_addresses(self, domain):
        dataset_url = 'https://github.com/martenson/disposable-email-domains/blob/master/disposable_email_blocklist.conf'

        print(f'[*] Checking Disposable Email Domains dataset')

        phish = set()
        resp = requests.get(dataset_url)
        if resp.ok:
            entries = [l.strip() for l in resp.text.split(os.linesep)]
            for entry in entries:
                if domain.lower() in entry.lower():
                    phish.add(entry)
        else:
            print(f'[-] Failed to download the dataset, status code: {resp.status_code}')
        if phish:
            print('-' * 50)
            print("[!] DEM DATASET - DOMAIN FOUND")
            for line in phish:
                print(line.replace(domain, colored(domain, 'red')))
            print('-' * 50)
        return phish

    def check_shodan(self, domain):
        print('[*] Searching Shodan for the general information')
        try:
            output = check_output(['shodan', 'domain', domain]).decode('utf-8')
            text = output.replace(domain, colored(domain, 'red')).replace(domain, colored(domain.upper(), 'red'))
            print(text)

            import re
            ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', text)
            if ips:
                for ip in ips:
                    try:
                        print(f'[*] Searching resolved IP {ip} on Shodan')
                        ip_search_output = check_output(['shodan', 'host', ip]).decode('utf-8')
                        print(ip_search_output.replace(domain, colored(domain, 'red')).replace(domain,
                                                                                               colored(domain.upper(),
                                                                                                       'red')))
                    except Exception as e:
                        print(e)

            return text
        except Exception as e:
            print(e)


def process_domain(domain):
    print(f"[*] '{domain}' - searching for cross-references in the phishing databases")

    radare = PhishRadare()
    radare.check_openphish_feed(domain)
    radare.check_phishstats(domain)
    radare.check_mitchellkrogza_database(domain)
    radare.check_phishtank(domain)
    radare.check_abuseipdb(domain)
    radare.check_alexa_top1m(domain)
    radare.check_binary_defense(domain)
    radare.check_ci_army_list(domain)
    radare.check_shodan(domain)
    radare.check_whois(domain)


options = get_arguments()

target = options.target
if target:
    if '@' in target:
        target = target.split('@')[1]
    if target.startswith('http'):
        target = urllib.parse.urlsplit(target).netloc
    process_domain(target)
