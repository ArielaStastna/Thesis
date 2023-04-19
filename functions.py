import socket
import random
from urllib.parse import urlparse
import randominfo
import metakeys_config
from faker import Faker

import os
import ipaddress
class Functions:
    
    fake=Faker()
    ip_dictionary={}
    ipv6_dictionary={}
    linklocal_dictionary = {}
    url_dictionary = {}
    email_dictionary = {}
    organizations_dictionary = {}
    mac_dictionary = {}
    name_dictionary = {}
    domains_dictionary = {}
    username_dictionary = {}
    linux_path_dictionary = {}
    win_path_dictionary = {}
    # Function to generate a random private IP address
    @staticmethod 
    def _generate_random_private_ip(private_range):
        # convert IP range strings to integers
        start = int(''.join(['{:08b}'.format(int(x)) for x in private_range['start'].split('.')]), 2)
        end = int(''.join(['{:08b}'.format(int(x)) for x in private_range['end'].split('.')]), 2)
    
        # generate a random integer within the IP range
        random_ip_int = random.randint(start, end)
    
        # convert the integer back to an IP address string
        random_ip_str = socket.inet_ntoa(int.to_bytes(random_ip_int, 4, 'big'))
    
        return random_ip_str
    
    # Function to anonymize an IP address
    @staticmethod 
    def anonymize_ip(ip_address):
        if ip_address in Functions.ip_dictionary:
            # If the IP address is already in the dictionary, return the corresponding anonymized IP address
            return Functions.ip_dictionary[ip_address]
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
                    anonymized_ip = Functions._generate_random_private_ip(private_range)
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
        Functions.ip_dictionary[ip_address] = anonymized_ip
    
        return anonymized_ip
    
    @staticmethod 
    def anonymize_ipv6(ipv6_address):
        # Check if the IPv6 address has already been anonymized
        if ipv6_address in Functions.ipv6_dictionary:
            # If yes, return the previously anonymized value
            return Functions.ipv6_dictionary[ipv6_address]
    
        # Split the IPv6 address into its 8 16-bit blocks
        blocks = ipv6_address.split(':')
    
        # Replace one random block with a new random value
        random_index = random.randint(0, 7)
        blocks[random_index] = '{:04x}'.format(random.randint(0, 2 ** 16 - 1))
    
        # Join the blocks back together into an IPv6 address
        anonymized_ipv6 = ':'.join(blocks)
    
        # Add the original and anonymized values to the dictionary
        Functions.ipv6_dictionary[ipv6_address] = anonymized_ipv6
    
        return anonymized_ipv6
    
    
    @staticmethod 
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
            if chunk in Functions.linklocal_dictionary:
                # If yes, use the same anonymized value
                anonymized_chunk = Functions.linklocal_dictionary[chunk]
            else:
                # If no, generate a new anonymized value
                anonymized_chunk = "".join([random.choice("0123456789abcdef") for _ in range(4)])
                Functions.linklocal_dictionary[chunk] = anonymized_chunk
    
            # Replace the original chunk with the anonymized value
            interface_id_chunks[i] = anonymized_chunk
    
        # Join the anonymized interface identifier chunks and reconstruct the full IPv6 address
        anonymized_interface_id = ":".join(interface_id_chunks)
        anonymized_ipv6_address = "fe80::" + anonymized_interface_id
    
        return anonymized_ipv6_address
    
    
    
    
    # Function to anonymize a MAC address
    @staticmethod 
    def anonymize_mac(mac):
        if mac in Functions.mac_dictionary:
            # Return previously anonymized MAC address
            return Functions.mac_dictionary[mac]
        else:
            # Generate random MAC address
            anonymized_mac = Functions.fake.mac_address()
            # Add anonymized MAC to dictionary
            Functions.mac_dictionary[mac] = anonymized_mac
            # Return anonymized MAC address
            return anonymized_mac
    
    @staticmethod 
    def _get_email():
        # Generate a random word to use in domain name
        word = Functions.fake.word()
        
        # Generate a random base domain name
        base_domain = Functions.fake.domain_name()
    
        c = random.randint(0, 2)
        dmn = '@' + base_domain
        if c == 0:
            email = randominfo.get_first_name() + randominfo.get_formatted_datetime("%Y", randominfo.get_birthdate(None), "%d %b, %Y") + dmn
        elif c == 1:
            email = randominfo.get_last_name() + randominfo.get_formatted_datetime("%d", randominfo.get_birthdate(None), "%d %b, %Y") + dmn
        else:
            email = randominfo.get_first_name() + randominfo.get_last_name() + randominfo.get_formatted_datetime("%y", randominfo.get_birthdate(None), "%d %b, %Y") + dmn
        return email
    
    # Function to anonymize an email address
    @staticmethod 
    def anonymize_email(email):
        if email in Functions.email_dictionary:
            # Return previously anonymized email address
            return Functions.email_dictionary[email]
        else:
            # Get random first and last names
            anonymized_email = Functions._get_email()
            # Add anonymized email to dictionary
            Functions.email_dictionary[email] = anonymized_email
            return anonymized_email
    
    @staticmethod 
    def anonymize_url(url):
        global url_dictionary
    
        # Check if the URL is already anonymized
        if url in url_dictionary:
            return url_dictionary[url]
    
        # Parse the URL into its components
        parts = urlparse(url)
    
        # Generate a random domain using the faker library
        domain = Functions.fake.domain_name()
    
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
    
    @staticmethod 
    def anonymize_domain(domain):
        if domain in Functions.domains_dictionary:
            return Functions.domains_dictionary[domain]
        else:
            anonymized_domain = Functions.fake.domain_name()
            Functions.domains_dictionary[domain] = anonymized_domain
            return anonymized_domain
    
    @staticmethod 
    def anonymize_name(name):
        # Check if the name has already been anonymized
        if name in Functions.name_dictionary:
            return Functions.name_dictionary[name]
    
        # Generate a new fake name and store it in the dictionary
        fake_name = Functions.fake.name()
        Functions.name_dictionary[name] = fake_name
    
        return fake_name
    
    @staticmethod 
    def anonymize_linux_path(path):
        if isinstance(path, tuple):
            # Convert the tuple to a string using os.path.abspath()
            path = os.path.abspath(os.path.join(*path))
    
        if not os.path.isabs(path):
            return path  # Return the original path if it's not absolute
    
        # Check if the path has been previously anonymized
        if path in Functions.linux_path_dictionary:
            return Functions.linux_path_dictionary[path]  # Return the previously anonymized path
    
        # Get the file extension (if it exists)
        filename, ext = os.path.splitext(path)
    
        # Generate a new random path in the Linux format
        new_path = os.path.join('/', *Functions.fake.words(nb=3, ext_word_list=None))
    
        # Add the original file extension (if it exists)
        if ext:
            new_path += ext
    
        # Add the newly generated path to the dictionary
        Functions.linux_path_dictionary[path] = new_path
    
        # Return the newly generated path
        return new_path
    
    # Functions.linux_path_dictionary = {}
    # fake = Faker()
    #
    # @staticmethod def anonymize_linux_path(path):
    #     if not os.path.isabs(path):
    #         return path  # Return the original path if it's not absolute
    #
    #     # Check if the path has been previously anonymized
    #     if path in Functions.linux_path_dictionary:
    #         return Functions.linux_path_dictionary[path]  # Return the previously anonymized path
    #
    #     # Get the file extension (if it exists)
    #     filename, ext = os.path.splitext(path)
    #
    #     # Generate a new random path in the Linux format
    #     new_path = os.path.join('/', *Functions.fake.words(nb=3, ext_word_list=None))
    #
    #     # Add the original file extension (if it exists)
    #     if ext:
    #         new_path += ext
    #
    #     # Add the newly generated path to the dictionary
    #     Functions.linux_path_dictionary[path] = new_path
    #
    #     # Return the newly generated path
    #     return new_path
    #
    
    @staticmethod 
    def anonymize_windows_path(path):
        if not os.path.isabs(path):
            return path  # Return the original path if it's not absolute
    
        # Check if the path has already been anonymized
        if path in Functions.win_path_dictionary:
            return Functions.win_path_dictionary[path]
    
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
                if component in Functions.win_path_dictionary:
                    # Use the previously generated anonymized name
                    anonymized_component = Functions.win_path_dictionary[component]
                else:
                    # Generate a new random directory name
                    anonymized_component = Functions.fake.word()
                    Functions.win_path_dictionary[component] = anonymized_component
    
                anonymized_components.append(anonymized_component)
    
        # Reconstruct the path with the anonymized components
        anonymized_path = drive + '\\' + '\\'.join(anonymized_components)
    
        # Store the anonymized path in the dictionary
        Functions.win_path_dictionary[path] = anonymized_path
    
        return anonymized_path
    
    @staticmethod 
    def anonymize_username(username):
        if username in Functions.username_dictionary :
            return Functions.username_dictionary [username]
        else:
            anonymized_username = Functions.fake.user_name()
            Functions.username_dictionary [username] = anonymized_username
            return anonymized_username
    
    @staticmethod 
    def anonymize_organization(org_name):
        if org_name in Functions.organizations_dictionary:
            # Return the previously anonymized value for this organization name
            return Functions.organizations_dictionary[org_name]
        else:
            # Generate a new fake company name
            fake_org_name = Functions.fake.company()
            # Add the new mapping to the dictionary
            Functions.organizations_dictionary[org_name] = fake_org_name
            # Return the anonymized company name
            return fake_org_name

    @staticmethod
    def clear_dicts():
        Functions.username_dictionary.clear()
        Functions.organizations_dictionary.clear()
        Functions.win_path_dictionary.clear()
        # Functions.linux_path_dictionary.clear()
        Functions.name_dictionary.clear()
        Functions.ip_dictionary.clear()
        Functions.ipv6_dictionary.clear()
        Functions.email_dictionary.clear()
        Functions.mac_dictionary.clear()
        Functions.domains_dictionary.clear()
        Functions.url_dictionary.clear()
        


