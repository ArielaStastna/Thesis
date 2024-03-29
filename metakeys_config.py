import functions
from functions import*
# from functions import anonymize_ip
# from functions import anonymize_ipv6
# from functions import anonymize_link_local_ipv6

class Elasticsearch:
    EMAIL_KEYS = (
    "email.bcc.address", "email.cc.address", "email.from.address", "email.reply_to.address", "email.sender.address",
    "email.to.address", "threat.enrichments.indicator.email.address", "threat.indicator.email.address", "user.email")
    IP_KEYS = ("client.ip", "client.nat.ip", "destination.ip", "destination.nat.ip", "host.ip", "observer.ip",
               "related.ip", "server.ip", "server.nat.ip", "source.ip", "source.nat.ip",
               "threat.enrichments.indicator.ip", "threat.indicator.ip", 'ip')
    DOMAIN_KEYS = ["TargetDomainName", "client.domain", "client.registrated_domain", "destination.domain", "destination.registrated_domain",
                   "server.domain", "source.domain", "source.registrated_domain", "url.domain", "user.domain", "host.name", 'computer_name']
    DIRECTORY_KEYS = ["file.directory", "file.path"]
    MAC_KEYS = ("observer.mac", "client.mac", "host.mac", "destination.mac", "server.mac", "source.mac")
    USERNAME_KEYS = ["user.name", "TargetUserName", 'host.hostname', 'AccountName']
    FULLNAME_KEYS = ["user.full_name"]
    URL_KEYS = ["url.full", "url.original"]
    ip_function_mapping = ["ipv4", "ipv6", "ipv6_local"]


class RSANetWitness:
    EMAIL_KEYS = ["email", "email.dst", "email.src"]
    IP4_KEYS = ["alias.ip", "device.ip", "ip.addr", "ip.dst", "ip.src", "tunnel.ip.dst", "tunnel.ip.src", "paddr"]
    IP6_KEYS=["alias.ipv6", "device.ipv6", "ipv6.dst", "ipv6.src", "tunnel.ipv6.dst", "tunnel.ipv6.src"]
    DOMAIN_KEYS =["ad.domain.dst", "ad.domain.src", "domain.dst", "domain.src"]
    MAC_KEYS = ["alias.mac", "eth.src", "eth.dst"]
    USERNAME_KEYS = ["ad.username.dst", "ad.username.src", "username"]
    FULLNAME_KEYS = ["fullname"]
    ORGANIZATION_KEYS=["org.dst", "org.src"]
class QRadar:
    EMAIL_KEYS = ["recipient-address", "sender-address", "related-recipient-address"]
    IP_KEYS = ["c-ip", "client-ip", "IPAddress", "InterfaceIP", "IP_MulticastScopeName", "IP_Name", "s-ip", "server-ip", "original-client-ip", "original-server-ip", "local-endpoint", "remote-endpoint"]
    DOMAIN_KEYS = ["Domain"]
    MAC_KEYS = ["MACAddress"]
    USERNAME_KEYS = ["cs-username", "UserName", "usrName", "client-hostname", "Hostname", "AccountName"]
    FULLNAME_KEYS = ["ClientName"]