import json
import sys
import pandas as pd
import re
import socket
import random
import randominfo
from faker import Faker
from urllib.parse import urlparse
import os
import ipaddress



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
         try:
            line = re.sub(ip, anonymize_ip(ip), line)
         except UnboundLocalError:
             continue
    print(sys.getsizeof(ip_dictionary))
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

def regex_linklocal(file):
    anon_log = ""
    df = pd.read_table(file)
    ip_pattern = re.compile(r'"(fe80:[0-9a-fA-F:]+)"')
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

def anonymize_linklocal_line(line):
    ip_pattern = re.compile(r'"(fe80:[0-9a-fA-F:]+)"')
    matches = ip_pattern.findall(line)  # find all matches meeting the regex condition

    for ipv6_address in matches:
         line = re.sub(ipv6_address, anonymize_link_local_ipv6(ipv6_address), line)
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
    url_pattern = re.compile('(?i)\b((?:https?:\/\/|www\.)\S+)\b')
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
    url_pattern = re.compile('(?i)\b((?:https?:\/\/|www\.)\S+)\b')
    matches = url_pattern.findall(line)
    for url in matches:
        line = re.sub(url, anonymize_url(url), line)
    return line
def regex_domain(file):
    anon_log = ""
    df = pd.read_table(file)
    domain_pattern = re.compile(r"\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
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
    mac_pattern = re.compile(r'[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}')
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
    linux_pattern = re.compile(r"(\/.*?\/)((?:[^\/]|\\\/)+?)(?:(?<!\\)\s|$)")
    matches = linux_pattern.findall(line)
    for path in matches:
        line = re.sub(path, anonymize_linux_path(path), line)
    return line

def regex_windows_directory(file):
    anon_log = ""
    df = pd.read_table(file)
    win_pattern = re.compile(
        r"[a-zA-Z]:\\((?:.*?\\)*).[^\s]*")
    with open(file, 'r', encoding="utf-8") as rf:
        while True:

            line = rf.readline()
            if not line:
                break
            matches = win_pattern.findall(line)
            for path in matches:
                line = re.sub(path, anonymize_windows_path(path), line)
            anon_log += line
    new_file = open('a.log', 'w', encoding="utf-8")
    new_file.write(anon_log)
    new_file.close()
    return anon_log

def anonymize_windows_line(line):
    win_pattern = re.compile((r"[a-zA-Z]:\\\\((?:.*?\\\\)*).[^\s]*"))
    matches = win_pattern.findall(line)
    for path in matches:
        line = re.sub(path, anonymize_windows_path(path), line)
    return line

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
    if ip_address in ip_dictionary:
        # If the IP address is already in the dictionary, return the corresponding anonymized IP address
        return ip_dictionary[ip_address]
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
    ip_dictionary[ip_address] = anonymized_ip

    return anonymized_ip

ipv6_dictionary={}


def anonymize_ipv6(ipv6_address):
    # Check if the IPv6 address has already been anonymized
    if ipv6_address in ipv6_dictionary:
        # If yes, return the previously anonymized value
        return ipv6_dictionary[ipv6_address]

    # Split the IPv6 address into its 8 16-bit blocks
    blocks = ipv6_address.split(':')

    # Replace one random block with a new random value
    random_index = random.randint(0, 7)
    blocks[random_index] = '{:04x}'.format(random.randint(0, 2 ** 16 - 1))

    # Join the blocks back together into an IPv6 address
    anonymized_ipv6 = ':'.join(blocks)

    # Add the original and anonymized values to the dictionary
    ipv6_dictionary[ipv6_address] = anonymized_ipv6

    return anonymized_ipv6
# Create Faker instance for generating fake MAC addresses
# Create a dictionary to store the anonymized interface IDs
anonymized_linklocal = {}

def anonymize_link_local_ipv6(ipv6_address):
    if not ipv6_address.startswith("fe80::"):
        return ipv6_address

    # Extract the interface identifier part of the IPv6 address
    interface_id = ipv6_address.split("::")[1]

    # Split the interface identifier into 2-byte chunks
    interface_id_chunks = [interface_id[i:i + 4] for i in range(0, len(interface_id), 4)]

    # Loop through each interface identifier chunk
    for i in range(len(interface_id_chunks)):
        chunk = interface_id_chunks[i]

        # Check if the current chunk has already been anonymized
        if chunk in anonymized_linklocal:
            # If yes, use the same anonymized value
            anonymized_chunk = anonymized_linklocal[chunk]
        else:
            # If no, generate a new anonymized value
            anonymized_chunk = "".join([random.choice("0123456789abcdef") for _ in range(4)])
            anonymized_linklocal[chunk] = anonymized_chunk

        # Replace the original chunk with the anonymized value
        interface_id_chunks[i] = anonymized_chunk

    # Join the anonymized interface identifier chunks and reconstruct the full IPv6 address
    anonymized_interface_id = ":".join(interface_id_chunks)
    anonymized_ipv6_address = "fe80::" + anonymized_interface_id

    return anonymized_ipv6_address
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
    if isinstance(path, tuple):
        # Convert the tuple to a string using os.path.abspath()
        path = os.path.abspath(os.path.join(*path))

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

# linux_path_dictionary = {}
# fake = Faker()
#
# def anonymize_linux_path(path):
#     if not os.path.isabs(path):
#         return path  # Return the original path if it's not absolute
#
#     # Check if the path has been previously anonymized
#     if path in linux_path_dictionary:
#         return linux_path_dictionary[path]  # Return the previously anonymized path
#
#     # Get the file extension (if it exists)
#     filename, ext = os.path.splitext(path)
#
#     # Generate a new random path in the Linux format
#     new_path = os.path.join('/', *fake.words(nb=3, ext_word_list=None))
#
#     # Add the original file extension (if it exists)
#     if ext:
#         new_path += ext
#
#     # Add the newly generated path to the dictionary
#     linux_path_dictionary[path] = new_path
#
#     # Return the newly generated path
#     return new_path
#


win_path_dictionary = {}
fake = Faker()

def anonymize_windows_path(path):
    if not os.path.isabs(path):
        return path  # Return the original path if it's not absolute

    # Check if the path has already been anonymized
    if path in win_path_dictionary:
        return win_path_dictionary[path]

    # Split the path into components
    drive, tail = os.path.splitdrive(str(path))
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
        line=str(line.decode("utf-8"))
        # .replace('\b', '').replace('\\r', '').replace('\\n', '').replace('\\t', '')
        line=anonymize_ipv4_line(line)
        line=anonymize_ipv6_line(line)
        line = anonymize_linklocal_line(line)
        line = anonymize_domain_line(line)
        line=anonymize_email_line(line)
        line = anonymize_url_line(line)
        line=anonymize_mac_line(line)
        #line=anonymize_linux_line(line)
        line = anonymize_windows_line(line)
        anon_log += line
    return anon_log


def clear_dicts(username_dictionary, organizations_dictionary, win_path_dictionary, linux_path_dictionary, name_dictionary, ip_dictionary, url_dictionary, ipv6_dictionary, mac_dictionary, email_dictionary, domains_dictionary):
    username_dictionary.clear()
    organizations_dictionary.clear()
    win_path_dictionary.clear()
    # linux_path_dictionary.clear()
    name_dictionary.clear()
    ip_dictionary.clear()
    ipv6_dictionary.clear()
    email_dictionary.clear()
    mac_dictionary.clear()
    domains_dictionary.clear()
    url_dictionary.clear()

def create_nested_key_structure(keys):
    nested_structure = {}  # Initialize an empty dictionary for the nested structure
    for key in keys:  # Loop through each key in the input list of keys
        parts = key.split(".")  # Split the key by "." to separate its parts
        current_level = nested_structure  # Set the current level of the nested structure to the top level
        for part in parts:  # Loop through each part of the key
            if part not in current_level:  # If the part is not already a key in the current level
                current_level[part] = {}  # Create a new nested dictionary for the part
            current_level = current_level[part]  # Update the current level to the nested dictionary for the part
    return nested_structure  # Return the completed nested structure

def process_nested_keys(data, keys, anonymization_function, elasticsearch):
    # If there is only one key remaining in the keys list
    if len(keys) == 1:
        # Check if the key exists in the data dictionary
        if keys[0] in data:
            # If the key is in the list of IP_KEYS in the elasticsearch object
            if keys[0] in elasticsearch.IP_KEYS:
                # If the value associated with the key is a list, apply the handle_ip_addresses function to each item in the list
                if isinstance(data[keys[0]], list):
                    data[keys[0]] = [handle_ip_addresses(item, elasticsearch) for item in data[keys[0]]]
                # If the value is not a list, apply the handle_ip_addresses function to the value
                else:
                    data[keys[0]] = handle_ip_addresses(data[keys[0]], elasticsearch)
            # If the key is not in the list of IP_KEYS
            else:
                # If the value associated with the key is a list, apply the anonymization_function to each item in the list
                if isinstance(data[keys[0]], list):
                    data[keys[0]] = [anonymization_function(item) for item in data[keys[0]]]
                # If the value is not a list, apply the anonymization_function to the value
                else:
                    data[keys[0]] = anonymization_function(data[keys[0]])
    # If there are still multiple keys remaining in the keys list
    else:
        key = keys[0]
        # Check if the key exists in the data dictionary
        if key in data:
            # Recursively call the process_nested_keys function on the value associated with the key
            # with the remaining keys in the keys list, anonymization_function, and elasticsearch as arguments
            process_nested_keys(data[key], keys[1:], anonymization_function, elasticsearch)

def handle_ip_addresses(ip, elasticsearch):
    try:
        # Try to create an ipaddress.ip_address object from the given IP
        ip_obj = ipaddress.ip_address(ip)
        # If the IP is IPv4
        if ip_obj.version == 4:
            # Return the result of applying the IPv4 anonymization function from the elasticsearch object on the IP
            return elasticsearch.ip_anonymization_mapping["ipv4"](ip)
        # If the IP is IPv6
        elif ip_obj.version == 6:
            # If the IPv6 IP is a link-local address
            if ip_obj.is_link_local:
                # Return the result of applying the link-local IPv6 anonymization function from the elasticsearch object on the IP
                return elasticsearch.ip_anonymization_mapping["ipv6_local"](ip)
            # If the IPv6 IP is not a link-local address
            else:
                # Return the result of applying the regular IPv6 anonymization function from the elasticsearch object on the IP
                return elasticsearch.ip_anonymization_mapping["ipv6"](ip)
        # If the given IP is not a valid IP address
    except ValueError:
        # Ignore the error and continue
        pass
        # Return the original IP if it was not successfully anonymized
    return ip

def anonymize_keys(data, key_anonymization_mapping, elasticsearch):
    if isinstance(data, dict):
        # Iterate over each key and its corresponding anonymization function in the key_anonymization_mapping
        for key, anonymization_function in key_anonymization_mapping.items():
            # Split the key by '.' to handle nested keys
            keys = key.split('.')
            # Call the process_nested_keys function to process the nested keys and apply the anonymization function
            process_nested_keys(data, keys, anonymization_function, elasticsearch)
        # Recursively call the anonymize_keys function on each value in the dictionary that is a dictionary or list
        for value in data.values():
            if isinstance(value, (dict, list)):
                anonymize_keys(value, key_anonymization_mapping, elasticsearch)
    elif isinstance(data, list):
        # Recursively call the anonymize_keys function on each item in the list
        for item in data:
            anonymize_keys(item, key_anonymization_mapping, elasticsearch)
        # Return the modified data after applying anonymization
    return data

def anonymize_data(data, elasticsearch):
    return anonymize_keys(data, elasticsearch.key_anonymization_mapping, elasticsearch)
class Elasticsearch:
    EMAIL_KEYS = (
    "email.bcc.address", "email.cc.address", "email.from.address", "email.reply_to.address", "email.sender.address",
    "email.to.address", "threat.enrichments.indicator.email.address", "threat.indicator.email.address", "user.email")
    IP_KEYS = ("client.ip", "client.nat.ip", "destination.ip", "destination.nat.ip", "host.ip", "observer.ip",
               "related.ip", "server.ip", "server.nat.ip", "source.ip", "source.nat.ip",
               "threat.enrichments.indicator.ip", "threat.indicator.ip", 'ip')
    DOMAIN_KEYS = ["TargetDomainName", "client.domain", "client.registrated_domain", "destination.domain", "destination.registrated_domain",
                   "server.domain", "source.domain", "source.registrated_domain", "url.domain", "user.domain", 'computer_name']
    DIRECTORY_KEYS = ["file.directory", "file.path"]
    MAC_KEYS = ("observer.mac", "client.mac", "host.mac", "destination.mac", "server.mac", "source.mac")
    USERNAME_KEYS = ["user.name", "host.name", "TargetUserName", 'host.hostname', 'AccountName']
    FULLNAME_KEYS = ["user.full_name"]
    URL_KEYS = ["url.full", "url.original"]

    key_anonymization_mapping = { # Create a dictionary that maps keys to anonymization functions
        **{key: anonymize_email for key in EMAIL_KEYS},
        **{key: anonymize_mac for key in MAC_KEYS},
        **{key: anonymize_domain for key in DOMAIN_KEYS},
        **{key: anonymize_ip for key in IP_KEYS},
        **{key: anonymize_username for key in USERNAME_KEYS},
        **{key: anonymize_url for key in URL_KEYS},
        **{key: anonymize_windows_path for key in DIRECTORY_KEYS},
        **{key: anonymize_name for key in FULLNAME_KEYS}
    }
    ip_anonymization_mapping = { # Create a dictionary that maps IP versions to their corresponding anonymization functions
        "ipv4": anonymize_ip,
        "ipv6": anonymize_ipv6,
        "ipv6_local": anonymize_link_local_ipv6
    }
