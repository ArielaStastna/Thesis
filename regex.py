import re
import sys
from functions import*

class Regex:
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
                line = re.sub(ip, Functions.anonymize_ip(ip), line)
             except UnboundLocalError:
                 continue
        print(sys.getsizeof(Functions.ip_dictionary))
        return line

    def anonymize_ipv6_line(line):
        ip_pattern = re.compile(r'\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b|\b(?:[a-fA-F0-9]{1,4}:){1,7}:(?::[a-fA-F0-9]{1,4}){1,6}\b')
        matches = ip_pattern.findall(line)  # find all matches meeting the regex condition

        for ipv6_address in matches:
             line = re.sub(ipv6_address, Functions.anonymize_ipv6(ipv6_address), line)
        return line


    def anonymize_linklocal_line(line):
        ip_pattern = re.compile(r'"(fe80:[0-9a-fA-F:]+)"')
        matches = ip_pattern.findall(line)  # find all matches meeting the regex condition

        for ipv6_address in matches:
             line = re.sub(ipv6_address, Functions.anonymize_link_local_ipv6(ipv6_address), line)
        return line

    def anonymize_email_line(line):
        email_pattern = re.compile(r"(?P<email_address>[\w\.-]+@[\w\.-]+\.[\w]+)")
        matches = email_pattern.findall(line)
        for email in matches:
            line = re.sub(email, Functions.anonymize_email(email), line)
        return line

    def anonymize_url_line(line):
        url_pattern = re.compile('(?i)\b((?:https?:\/\/|www\.)\S+)\b')
        matches = url_pattern.findall(line)
        for url in matches:
            line = re.sub(url, Functions.anonymize_url(url), line)
        return line

    def anonymize_domain_line(line):
        domain_pattern = re.compile(r'\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
        matches = domain_pattern.findall(line)
        for domain in matches:
            line = re.sub(domain, Functions.anonymize_domain(domain), line)
        return line

    def anonymize_mac_line(line):
        mac_pattern = re.compile(r'[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}')
        matches = mac_pattern.findall(line)
        for mac in matches:
            line = re.sub(mac, Functions.anonymize_mac(mac), line)
        return line


    def anonymize_linux_line(line):
        linux_pattern = re.compile(r"(\/.*?\/)((?:[^\/]|\\\/)+?)(?:(?<!\\)\s|$)")
        matches = linux_pattern.findall(line)
        for path in matches:
            line = re.sub(path, Functions.anonymize_linux_path(path), line)
        return line

    def anonymize_windows_line(line):
        win_pattern = re.compile((r"[a-zA-Z]:\\\\((?:.*?\\\\)*).[^\s]*"))
        matches = win_pattern.findall(line)
        for path in matches:
            line = re.sub(path, Functions.anonymize_windows_path(path), line)
        return line
    def complete_anonymization(logs):
        anon_log=""

        while True:

            line = logs.readline()
            if not line:
                break
            line=str(line.decode("utf-8"))
            line= Regex.anonymize_ipv4_line(line)
            line= Regex.anonymize_ipv6_line(line)
            line = Regex.anonymize_linklocal_line(line)
            line = Regex.anonymize_domain_line(line)
            line=Regex.anonymize_email_line(line)
            line = Regex.anonymize_url_line(line)
            line=Regex.anonymize_mac_line(line)
            #line=anonymize_linux_line(line)
            line = Regex.anonymize_windows_line(line)
            anon_log += line
        return anon_log
