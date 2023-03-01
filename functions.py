import pandas as pd
import re
import socket
import random
import randominfo
from faker import Faker
import string
from urllib.parse import urlparse
import os


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

def regex_url(file):
    df = pd.read_table(file)
    ip_pattern = re.compile(r"(?i)\b((?:https?://|www\.)\S+)\b")
    with open(file, 'r', encoding="utf-8") as rf:
        content = rf.read()
        matches = ip_pattern.findall(content)
    return matches

def regex_mac(file):
    df = pd.read_table(file)
    ip_pattern = re.compile(
        r"[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}")
    with open(file, 'r', encoding="utf-8") as rf:
        content = rf.read()
        matches = ip_pattern.findall(content)
    return matches


def regex_linux_directory(file):
    df = pd.read_table(file)
    ip_pattern = re.compile(r"(\/.*?\/)((?:[^\/]|\\\/)+?)(?:(?<!\\)\s|$)")
    with open(file, 'r') as rf:
        content = rf.read()
        matches = ip_pattern.findall(content)
    return matches


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
anonymized_macs = {}

# Function to anonymize a MAC address
def anonymize_mac(mac):
    if mac in anonymized_macs:
        # Return previously anonymized MAC address
        return anonymized_macs[mac]
    else:
        # Generate random MAC address
        anonymized_mac = fake.mac_address()
        # Add anonymized MAC to dictionary
        anonymized_macs[mac] = anonymized_mac
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
anonymized_emails = {}

# Function to anonymize an email address
def anonymize_email(email):
    if email in anonymized_emails:
        # Return previously anonymized email address
        return anonymized_emails[email]
    else:
        # Get random first and last names
        anonymized_email = get_email()
        # Add anonymized email to dictionary
        anonymized_emails[email] = anonymized_email
        return anonymized_email

anonymized_urls = {}
def anonymize_url(url):
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

    return new_url

anonymized_names = {}
def anonymize_name(name):
    fake = Faker()
    fake.name() # initialize the provider to generate names
    return fake.name()

anonymized_linux_paths = {}
fake = Faker()

def anonymize_linux_path(path):
    if not os.path.isabs(path):
        return path  # Return the original path if it's not absolute

    # Get the file extension (if it exists)
    filename, ext = os.path.splitext(path)

    # Generate a new random path in the Linux format
    new_path = os.path.join('/', *fake.words(nb=3, ext_word_list=None))

    # Add the original file extension (if it exists)
    if ext:
        new_path += ext

    # Replace the original path with the new path
    return new_path

anonymized_win_paths = {}
fake = Faker()

def anonymize_windows_path(path):
    if not os.path.isabs(path):
        return path  # Return the original path if it's not absolute

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
            # Generate a new random directory name
            anonymized_components.append(fake.word())

    # Reconstruct the path with the anonymized components
    anonymized_path = drive + '\\' + '\\'.join(anonymized_components)
    return anonymized_path

anonymized_usernames = {}
fake = Faker()

def anonymize_username(username):
    return fake.user_name()

anonymized_organizations = {}
def anonymize_organization(org_name):
    fake = Faker()
    return fake.company()