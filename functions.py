import pandas as pd
import re
import socket
import random
import randominfo
from faker import Faker


def print_original(log):
    for i in log:
        print(i)
        print("\n")
def regex_ipv4(file):
    df = pd.read_table(file)  # using pandas library for big data
    ip_pattern = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')  # regex for IPv4

    # matches=""

    with open(file, 'r',
              encoding="utf-8") as rf:  # necessity to change to type of enconding to utf-8 to be able to read the file
        content = rf.read()
        matches = ip_pattern.findall(content)  # find all matches meeting the regex condition
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
    return matches


def regex_ipv6(file):
    df = pd.read_table(file)
    ip_pattern = re.compile(r'(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})')
    # matches=""
    with open(file, 'r', encoding="utf-8") as rf:
        content = rf.read()
        matches = ip_pattern.findall(content)
    return matches


def regex_email(file):
    df = pd.read_table(file)
    ip_pattern = re.compile(r"(?P<email_address>[\w\.-]+@[\w\.-]+\.[\w]+)")
    # matches=""
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
# Create an instance of RandomInfo
# ri = Person()
#
# # Dictionary to keep track of previously anonymized email addresses
# anonymized_emails = {}
#
#
# # Function to generate a random email address
# def generate_random_email(first_name, last_name):
#     domain = random.choice(
#         ['gmail.com', 'hotmail.com', 'yahoo.com', 'outlook.com', 'aol.com', 'protonmail.com', 'mail.com',
#          'tutanota.com', 'zoho.com', 'gmx.com', 'icloud.com', 'yandex.com', 'inbox.com', 'fastmail.com', 'runbox.com',
#          'posteo.de', 'web.de', 'gmx.net', 'yahoo.co.uk', 'btinternet.com', 'aol.co.uk', 'mail.ru', 'abv.bg',
#          't-online.de', 'online.no', 'providor.it', 'laposte.net', 'mail.bg', 'telia.com', 'sfr.fr', 'live.no',
#          'online.nl', 'free.fr', 'home.nl', 'eircom.net', 'poczta.onet.pl', 'verizon.net', 'wanadoo.fr', 'bluewin.ch',
#          'wp.pl', 'wanadoo.nl', 'hetnet.nl', 'chello.nl', 'swissonline.ch', 'virginmedia.com', 'orange.fr',
#          'orange.net', 'tele2.nl', 'numericable.fr', 'btconnect.com', 'videotron.ca', 'virgin.net', 'charter.net',
#          'comcast.net', 'earthlink.net', 'att.net', 'cox.net', 'pacbell.net', 'sbcglobal.net', 'shaw.ca',
#          'sympatico.ca', 'telus.net'])
#     username = first_name.lower() + '.' + last_name.lower() + str(
#         random.randint(0, 999) if random.random() < 0.2 else '')
#     email = username + '@' + domain
#     return email
#
#
# # Function to anonymize an email address
# def anonymize_email(email):
#     if email in anonymized_emails:
#         # Return previously anonymized email address
#         return anonymized_emails[email]
#     else:
#         # Get random first and last names
#         first_name = ri.get_first_name()
#         last_name = ri.get_last_name()
#         # Generate random email address
#         anonymized_email = generate_random_email(first_name, last_name)
#         # Add anonymized email to dictionary
#         anonymized_emails[email] = anonymized_email
#         return anonymized_email
#
#
# # def generate_random_email():
#     ri = RandomInfo()
#     first_name = ri.first_name()
#     last_name = ri.last_name()
#     domain_list = ['gmail.com', 'hotmail.com', 'yahoo.com', 'outlook.com', 'aol.com', 'protonmail.com', 'mail.com', 'tutanota.com', 'zoho.com', 'gmx.com', 'icloud.com', 'yandex.com', 'inbox.com', 'fastmail.com', 'runbox.com', 'posteo.de', 'web.de', 'gmx.net', 'yahoo.co.uk', 'btinternet.com', 'aol.co.uk', 'mail.ru', 'abv.bg', 't-online.de', 'online.no', 'providor.it', 'laposte.net', 'mail.bg', 'telia.com', 'sfr.fr', 'live.no', 'online.nl', 'free.fr', 'home.nl', 'eircom.net', 'poczta.onet.pl', 'verizon.net', 'wanadoo.fr', 'bluewin.ch', 'wp.pl', 'wanadoo.nl', 'hetnet.nl', 'chello.nl', 'swissonline.ch', 'virginmedia.com', 'orange.fr', 'orange.net', 'tele2.nl', 'numericable.fr', 'btconnect.com', 'videotron.ca', 'virgin.net', 'charter.net', 'comcast.net', 'earthlink.net', 'att.net', 'cox.net', 'pacbell.net', 'sbcglobal.net', 'shaw.ca', 'sympatico.ca', 'telus.net']
#     domain = random.choice(domain_list)
#     email = ""
#     if random.choice([True, False]):
#         email += first_name.lower() + '.'
#     if random.choice([True, False]):
#         email += last_name.lower() + '.'
#     if random.choice([True, False]):
#         email += str(random.randint(0, 999)) + '.'
#     email += domain
#     return email

