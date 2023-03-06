import json

import pandas as pd
import re
import socket
import random
import randominfo
from faker import Faker
import string
from urllib.parse import urlparse
import os

from metakeys_config import Elasticsearch


def print_original(log):
    for i in log:
        print(i)
        print("\n")
def regex_ipv4(file):
    anon_log= ""
    df = pd.read_table(file)  # using pandas library for big data
    ip_pattern = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')  # regex for IPv4

    # matches=""

    with open(file, 'r',
              encoding="utf-8") as rf:  # necessity to change to type of enconding to utf-8 to be able to read the file
        while True:

            line = rf.readline()
            if not line:
                break

            matches = ip_pattern.findall(line)  # find all matches meeting the regex condition
            for ip in matches:  # validation of matches for 0-255 range to prevent false matches
                tmp = ip.split(".")
                if (int(tmp[0]) > 255):
                    matches.remove(ip)
                elif (int(tmp[1]) > 255):
                    matches.remove(ip)
                elif (int(tmp[2]) > 255):
                    matches.remove(ip)
                elif (int(tmp[3]) > 255):
                    matches.remove(ip)
            for ip in matches:
                line=re.sub(ip,anonymize_ip(ip),line)
            anon_log+=line
    new_file=open('anonymized.log', 'w')
    new_file.write(anon_log)
    new_file.close()
    return anon_log

def anonymize_ipv4_line(line):
    ip_pattern = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')  # regex for IPv4
    matches = ip_pattern.findall(line)  # find all matches meeting the regex condition
    for ip in matches:  # validation of matches for 0-255 range to prevent false matches
        tmp = ip.split(".")
        if (int(tmp[0]) > 255):
            matches.remove(ip)
        elif (int(tmp[1]) > 255):
            matches.remove(ip)
        elif (int(tmp[2]) > 255):
            matches.remove(ip)
        elif (int(tmp[3]) > 255):
            matches.remove(ip)
    for ip in matches:
        line=re.sub(ip,anonymize_ip(ip),line)
    return line
def regex_ipv6(file):
    anon_log = ""
    df = pd.read_table(file)
    ip_pattern = re.compile(r'\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b|\b(?:[a-fA-F0-9]{1,4}:){1,7}:(?::[a-fA-F0-9]{1,4}){1,6}\b')
    # ip_pattern = re.compile(r'(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})')
    with open(file, 'r', encoding="utf-8") as rf:
        content = rf.readlines()
        while True:

            line = rf.readline()
            if not line:
                break
            matches = ip_pattern.findall(line)  # find all matches meeting the regex condition

            for ipv6_address in matches:
                 line = re.sub(ipv6_address, anonymize_ipv6(ipv6_address), line)
            anon_log += line
    new_file = open('a.log', 'w')
    new_file.write(anon_log)
    new_file.close()
    return anon_log

def anonymize_ipv6_line(line):
    ip_pattern = re.compile(r'\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b|\b(?:[a-fA-F0-9]{1,4}:){1,7}:(?::[a-fA-F0-9]{1,4}){1,6}\b')
    matches = ip_pattern.findall(line)  # find all matches meeting the regex condition

    for ipv6_address in matches:
         line = re.sub(ipv6_address, anonymize_ipv6(ipv6_address), line)
    return line
def regex_email(file):
    anon_log = ""
    df = pd.read_table(file)
    email_pattern = re.compile(r"(?P<email_address>[\w\.-]+@[\w\.-]+\.[\w]+)")
    # matches=""
    with open(file, 'r', encoding="utf-8") as rf:
        while True:

            line = rf.readline()
            if not line:
                break
            matches = email_pattern.findall(line)
            for email in matches:
                line = re.sub(email, anonymize_email(email), line)
            anon_log += line
    new_file = open('a.log', 'w', encoding="utf-8")
    new_file.write(anon_log)
    new_file.close()
    return anon_log

def anonymize_email_line(line):
    email_pattern = re.compile(r"(?P<email_address>[\w\.-]+@[\w\.-]+\.[\w]+)")
    matches = email_pattern.findall(line)
    for email in matches:
        line = re.sub(email, anonymize_email(email), line)
    return line

def regex_url(file):
    anon_log = ""
    df = pd.read_table(file)
    url_pattern = re.compile(r'(?i)\b((?:https?:\/\/|www\.)\S+)\b')
    with open(file, 'r', encoding="utf-8") as rf:
        while True:

            line = rf.readline()
            if not line:
                break
            matches = url_pattern.findall(line)
            for url in matches:
                line = re.sub(url, anonymize_url(url), line)
            anon_log += line
    new_file = open('a.log', 'w', encoding="utf-8")
    new_file.write(anon_log)
    new_file.close()
    return anon_log

def anonymize_url_line(line):
    url_pattern = re.compile(r'(?i)\b((?:https?:\/\/|www\.)\S+)\b')
    matches = url_pattern.findall(line)
    for url in matches:
        line = re.sub(url, anonymize_url(url), line)
    return line
def regex_domain(file):
    anon_log = ""
    df = pd.read_table(file)
    domain_pattern = re.compile(r'\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
    with open(file, 'r', encoding="utf-8") as rf:
        while True:

            line = rf.readline()
            if not line:
                break
            matches = domain_pattern.findall(line)
            for domain in matches:
                line = re.sub(domain, anonymize_domain(domain), line)
            anon_log += line
    new_file = open('a.log', 'w', encoding="utf-8")
    new_file.write(anon_log)
    new_file.close()
    return anon_log

def anonymize_domain_line(line):
    domain_pattern = re.compile(r'\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
    matches = domain_pattern.findall(line)
    for domain in matches:
        line = re.sub(domain, anonymize_domain(domain), line)
    return line
def regex_mac(file):
    anon_log = ""
    df = pd.read_table(file)
    mac_pattern = re.compile(r"[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}")
    with open(file, 'r', encoding="utf-8") as rf:
        while True:

            line = rf.readline()
            if not line:
                break
            matches = mac_pattern.findall(line)
            for mac in matches:
                line = re.sub(mac, anonymize_mac(mac), line)
            anon_log += line
    new_file = open('a.log', 'w', encoding="utf-8")
    new_file.write(anon_log)
    new_file.close()
    return anon_log

def anonymize_mac_line(line):
    mac_pattern = re.compile(r'\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
    matches = mac_pattern.findall(line)
    for mac in matches:
        line = re.sub(mac, anonymize_mac(mac), line)
    return line

def regex_linux_directory(file):
    anon_log = ""
    df = pd.read_table(file)
    linux_pattern = re.compile(
        r"(\/.*?\/)((?:[^\/]|\\\/)+?)(?:(?<!\\)\s|$)")
    with open(file, 'r', encoding="utf-8") as rf:
        while True:

            line = rf.readline()
            if not line:
                break
            matches = linux_pattern.findall(line)
            for path in matches:
                line = re.sub(path, anonymize_linux_path(path), line)
            anon_log += line
    new_file = open('a.log', 'w', encoding="utf-8")
    new_file.write(anon_log)
    new_file.close()
    return anon_log

def anonymize_linux_line(line):
    linux_pattern = re.compile(r"(\/.*?\/)((?:[^\/]|\\\/)+?)(?:(?<!\\\\)\s|$)")
    matches = linux_pattern.findall(line)
    for path, _ in matches:
        line = re.sub(path, anonymize_linux_path(path), line)
    return line

def regex_windows_directory(file):
    df = pd.read_table(file)
    ip_pattern = re.compile(r"[a-zA-Z]:\\((?:.*?\\)*).[^\s]*")
    with open(file, 'r', encoding="utf-8") as rf:
        content = rf.read()
        matches = ip_pattern.findall(content)
    return matches


# Function to generate a random private IP address
def generate_random_private_ip(private_range):
    # convert IP range strings to integers
    start = int(''.join(['{:08b}'.format(int(x)) for x in private_range['start'].split('.')]), 2)
    end = int(''.join(['{:08b}'.format(int(x)) for x in private_range['end'].split('.')]), 2)

    # generate a random integer within the IP range
    random_ip_int = random.randint(start, end)

    # convert the integer back to an IP address string
    random_ip_str = socket.inet_ntoa(int.to_bytes(random_ip_int, 4, 'big'))

    return random_ip_str

ip_dictionary={}
# Function to anonymize an IP address
def anonymize_ip(ip_address):
    # Define private and public IP address ranges
    private_ranges = [
        {"start": "10.0.0.0", "end": "10.255.255.255"},
        {"start": "172.16.0.0", "end": "172.31.255.255"},
        {"start": "192.168.0.0", "end": "192.168.255.255"}
    ]
    public_ranges = [
        {"start": "0.0.0.0", "end": "9.255.255.255"},
        {"start": "11.0.0.0", "end": "172.15.255.255"},
        {"start": "172.32.0.0", "end": "192.167.255.255"},
        {"start": "192.169.0.0", "end": "223.255.255.255"}
    ]

    is_private = False
    for private_range in private_ranges:
        if (socket.inet_aton(ip_address) >= socket.inet_aton(private_range['start'])) and (
                socket.inet_aton(ip_address) <= socket.inet_aton(private_range['end'])):
            is_private = True
            break

    if is_private:
        # Replace private IP address with a random one in the same range
        for private_range in private_ranges:
            if (socket.inet_aton(ip_address) >= socket.inet_aton(private_range['start'])) and (
                    socket.inet_aton(ip_address) <= socket.inet_aton(private_range['end'])):
                anonymized_ip = generate_random_private_ip(private_range)
                break
    else:
        # Replace public IP address with a random one in the same range
        for public_range in public_ranges:
            if (socket.inet_aton(ip_address) >= socket.inet_aton(public_range['start'])) and (
                    socket.inet_aton(ip_address) <= socket.inet_aton(public_range['end'])):
                start = int(''.join(['{:08b}'.format(int(x)) for x in public_range['start'].split('.')]), 2)
                end = int(''.join(['{:08b}'.format(int(x)) for x in public_range['end'].split('.')]), 2)
                random_ip_int = random.randint(start, end)
                anonymized_ip = socket.inet_ntoa(int.to_bytes(random_ip_int, 4, 'big'))
                break

    return anonymized_ip

ipv6_dictionary={}
def anonymize_ipv6(ipv6_address):
    # Split the IPv6 address into its 8 16-bit blocks
    blocks = ipv6_address.split(':')

    # Replace one random block with a new random value
    random_index = random.randint(0, 7)
    blocks[random_index] = '{:04x}'.format(random.randint(0, 2**16-1))

    # Join the blocks back together into an IPv6 address
    anonymized_ipv6 = ':'.join(blocks)

    return anonymized_ipv6
# Create Faker instance for generating fake MAC addresses
fake = Faker()

# Dictionary to keep track of previously anonymized MAC addresses
mac_dictionary = {}

# Function to anonymize a MAC address
def anonymize_mac(mac):
    if mac in mac_dictionary:
        # Return previously anonymized MAC address
        return mac_dictionary[mac]
    else:
        # Generate random MAC address
        anonymized_mac = fake.mac_address()
        # Add anonymized MAC to dictionary
        mac_dictionary[mac] = anonymized_mac
        # Return anonymized MAC address
        return anonymized_mac

fake=Faker()
def get_email():
    # Generate a random word to use in domain name
    word = fake.word()

    # Generate a random base domain name
    base_domain = fake.domain_name()

    # domains = ["gmail", "yahoo", "hotmail", "express", "yandex", "nexus", "online", "omega", "institute", "finance",
    #            "company", "management", "chello", "tmobile", "corporation", "community", "email", "vutbr", "outlook", "seznam", "t-mobile", "orange", "icloud", "aol", "orange", "protonmail", "fastmail"]
    # extentions = ['com', 'in', 'jp', 'us', 'uk', 'org', 'edu', 'au', 'de', 'co', 'me', 'biz', "cz", "sk", "fr", "hu", "es", "nl", "be", "pl", "ru", 'dev', 'ngo', 'site',
    #               'xyz', 'zero', 'tech']


    c = random.randint(0, 2)
    dmn = '@' + base_domain
    # dmn = '@' + random.choice(domains)
    # ext = random.choice(extentions)
    # + "."  + ext
    if c == 0:
        email = randominfo.get_first_name() + randominfo.get_formatted_datetime("%Y", randominfo.get_birthdate(None), "%d %b, %Y") + dmn
    elif c == 1:
        email = randominfo.get_last_name() + randominfo.get_formatted_datetime("%d", randominfo.get_birthdate(None), "%d %b, %Y") + dmn
    else:
        email = randominfo.get_first_name() + randominfo.get_last_name() + randominfo.get_formatted_datetime("%y", randominfo.get_birthdate(None), "%d %b, %Y") + dmn
    return email
# Dictionary to keep track of previously anonymized email addresses
email_dictionary = {}

# Function to anonymize an email address
def anonymize_email(email):
    if email in email_dictionary:
        # Return previously anonymized email address
        return email_dictionary[email]
    else:
        # Get random first and last names
        anonymized_email = get_email()
        # Add anonymized email to dictionary
        email_dictionary[email] = anonymized_email
        return anonymized_email


url_dictionary = {}


def anonymize_url(url):
    global url_dictionary

    # Check if the URL is already anonymized
    if url in url_dictionary:
        return url_dictionary[url]

    # Parse the URL into its components
    parts = urlparse(url)

    # Generate a random domain using the faker library
    faker = Faker()
    domain = faker.domain_name()

    # Construct a new URL using the random domain
    new_url = f"{parts.scheme}://{domain}{parts.path}"

    # Add any query parameters or fragments back to the new URL
    if parts.query:
        new_url += f"?{parts.query}"
    if parts.fragment:
        new_url += f"#{parts.fragment}"

    # Add the anonymized URL to the dictionary
    url_dictionary[url] = new_url

    return new_url

domains_dictionary = {}
def anonymize_domain(domain):
    if domain in domains_dictionary:
        return domains_dictionary[domain]
    else:
        fake = Faker()
        anonymized_domain = fake.domain_name()
        domains_dictionary[domain] = anonymized_domain
        return anonymized_domain
name_dictionary = {}


def anonymize_name(name):
    # Check if the name has already been anonymized
    if name in name_dictionary:
        return name_dictionary[name]

    # Generate a new fake name and store it in the dictionary
    fake_name = fake.name()
    name_dictionary[name] = fake_name

    return fake_name
linux_path_dictionary = {}
fake = Faker()

def anonymize_linux_path(path):
    if not os.path.isabs(path):
        return path  # Return the original path if it's not absolute

    # Check if the path has been previously anonymized
    if path in linux_path_dictionary:
        return linux_path_dictionary[path]  # Return the previously anonymized path

    # Get the file extension (if it exists)
    filename, ext = os.path.splitext(path)

    # Generate a new random path in the Linux format
    new_path = os.path.join('/', *fake.words(nb=3, ext_word_list=None))

    # Add the original file extension (if it exists)
    if ext:
        new_path += ext

    # Add the newly generated path to the dictionary
    linux_path_dictionary[path] = new_path

    # Return the newly generated path
    return new_path


win_path_dictionary = {}
fake = Faker()

def anonymize_windows_path(path):
    if not os.path.isabs(path):
        return path  # Return the original path if it's not absolute

    # Check if the path has already been anonymized
    if path in win_path_dictionary:
        return win_path_dictionary[path]

    # Split the path into components
    drive, tail = os.path.splitdrive(path)
    path_components = tail.split('\\')

    # Anonymize the path components
    anonymized_components = []
    for component in path_components:
        if component in ('Windows', 'Program Files', 'Program Files (x86)', 'Users', 'System32'):
            # Preserve common directories
            anonymized_components.append(component)
        else:
            if component in win_path_dictionary:
                # Use the previously generated anonymized name
                anonymized_component = win_path_dictionary[component]
            else:
                # Generate a new random directory name
                anonymized_component = fake.word()
                win_path_dictionary[component] = anonymized_component

            anonymized_components.append(anonymized_component)

    # Reconstruct the path with the anonymized components
    anonymized_path = drive + '\\' + '\\'.join(anonymized_components)

    # Store the anonymized path in the dictionary
    win_path_dictionary[path] = anonymized_path

    return anonymized_path


username_dictionary = {}
def anonymize_username(username):
    if username in username_dictionary :
        return username_dictionary [username]
    else:
        anonymized_username = fake.user_name()
        username_dictionary [username] = anonymized_username
        return anonymized_username

organizations_dictionary = {}
def anonymize_organization(org_name):
    if org_name in organizations_dictionary:
        # Return the previously anonymized value for this organization name
        return organizations_dictionary[org_name]
    else:
        # Generate a new fake company name
        fake_org_name = fake.company()
        # Add the new mapping to the dictionary
        organizations_dictionary[org_name] = fake_org_name
        # Return the anonymized company name
        return fake_org_name

def complete_anonymization(logs):
    anon_log=""

    while True:

        line = logs.readline()
        if not line:
            break
        line=str(line)
        line=anonymize_ipv4_line(line)
        line=anonymize_ipv6_line(line)
        line=anonymize_email_line(line)
        line = anonymize_url_line(line)
        line=anonymize_domain_line(line)
        line=anonymize_mac_line(line)
        line=anonymize_linux_line(line)
        anon_log += line
    return anon_log

def read_json(logs):
    metavalues=[]

    #fileData = logs.read()
    jsonData = json.loads(logs)
    jsonData=str(jsonData)
    obj=Elasticsearch()
    for metakey in obj.IP_KEYS:
        try:

            metavalues.append(jsonData[metakey])
        except KeyError:
            pass
    return metavalues

