
from flask import Flask, render_template
import psycopg2
from functions import*
from time import perf_counter
import json
import ipaddress

app = Flask(__name__)

def db_connection():#connection to DB using psycopg2 library
    conn = psycopg2.connect(database="thesis",
                            host="localhost",
                            user="xyz",#zmenit
                            password="xyz",
                            port=5432
                            )
    return conn
@app.route('/settings')
def settings():
    return render_template ("settings.html")
#function looking for IPv4 matches in log files
def ip():
    t1_start = perf_counter()
    matches = regex_ipv4('files/waf.log') # calling function with the regex;
    print_original(matches)#calling function for printing matches into console
    t2_end = perf_counter()#function used for performance testing
    print(t1_start)
    print(t2_end)
    return matches
@app.route('/')
def index():
    return render_template("index.html")
@app.route('/ipv4')
def ipv4():
    # matches = ip()
    # anonymized = []
    #
    # for addr in matches:
    #         ipaddr = str(ipaddress.ip_address(addr))
    #         anonymized.append(str(anonymize_ip(ipaddr)))
    return regex_ipv4('files/waf.log')
# @app.route('/ipv4')
# def ipv4():
#     matches = ip()
#     anonymized = []
#     for i in matches:
#         anonymized_ip = anonymize_ip(i)
#         # if anonymized_ip is None:
#         #     # If the input is not a valid IPv4 address, return an error message.
#         #     return jsonify({'error': f'{i} is not a valid IPv4 address.'}), 400
#         # else:
#         anonymized.append(anonymized_ip)
#     return jsonify(anonymized)

@app.route('/ipv6')
def ipv6():
    matches = regex_ipv6("files/linux.log")
    print_original(matches)
    return matches
@app.route('/mail')
def mail():
    matches=email()
    anonymized=[]
    for address in matches:
        emailadd=address
        anonymized.append(anonymize_email(emailadd))
    return anonymized
@app.route('/mac')
def mac():
    matches=parse_log_mac('windows-log-radka.json')
    return matches

def email():
    t1_start = perf_counter()
    matches = regex_email("singlelog.log")
    print_original(matches)
    t2_end = perf_counter()
    print(t1_start)
    print(t2_end)
    return matches
@app.route('/mac_addr')
def mac_addr():
    matches=mac_address()
    anonymized=[]
    for address in matches:
        macadd=address
        anonymized.append(anonymize_mac(macadd))
    return anonymized

def mac_address():
    t1_start = perf_counter()
    matches = regex_mac("files/fortinet.log")
    print_original(matches)
    t2_end = perf_counter()
    print(t1_start)
    print(t2_end)
    return matches
    # df = pd.read_table("dataset.txt")
    # ip_pattern = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
    # matches=""
    # if not os.path.exists("iters.txt"):
    #     with open('dataset.txt', 'r') as rf, open('iters.txt', 'a') as wf:
    #         content = rf.read()
    #         matches = ip_pattern.findall(content)
    #         for match in matches:
    #             wf.write(match + '\n')
    # return matches

@app.route('/linux-directory')
def linux_directory():
    matches = regex_linux_directory("files/linux.log")
    print_original(matches)
    return matches
@app.route('/windows-directory')
def windows_directory():
    t1_start = perf_counter()
    matches = regex_windows_directory("files/windows.log")
    print_original(matches)
    t2_end = perf_counter()
    print(t1_start)
    print(t2_end)
    return matches
@app.route('/findall')
def findall():
    windows_directory()
    mac_address()
    email()
    ip()
    return "Check your console."
@app.route('/ipdb')#function for filling the database
def ipdb():
        matches = ip()
        conn = db_connection()
        cur = conn.cursor()
        for singleIP in matches: #every single match is stored in database
            cur.execute("INSERT INTO anon_ip (original, id_category) VALUES (%s, 1)", [singleIP])#the id_category refers to the category of sensitive data
        conn.commit()
        cur.close()
        conn.close()
        return "IP address values successfully added to the database!"
@app.route('/emaildb')
def emaildb():
    matches = email()
    conn = db_connection()
    cur = conn.cursor()
    for single_email in matches:
        cur.execute("INSERT INTO anon_email (original, id_category) VALUES (%s, 5)", [single_email])
    conn.commit()
    cur.close()
    conn.close()
    return "Email values successfully added to the database!"
@app.route('/macdb')
def macdb():
    matches = mac_address()
    conn = db_connection()
    cur = conn.cursor()
    for singleMAC in matches:
        cur.execute("INSERT INTO anon_mac (original, id_category) VALUES (%s, 2)", [singleMAC])
    conn.commit()
    cur.close()
    conn.close()
    return "MAC address values successfully added to the database!"
@app.route('/directorydb')
def directorydb():
    matches = windows_directory()
    conn = db_connection()
    cur = conn.cursor()
    for single_directory in matches:
        cur.execute("INSERT INTO anon_windows_directory (original, id_category) VALUES (%s, 13)", [single_directory])
    conn.commit()
    cur.close()
    conn.close()
    return "Directory values successfully added to the database!"
@app.route('/directorylinux')
def directory_linux_db():
    matches = linux_directory()
    conn = db_connection()
    cur = conn.cursor()
    for single_directory in matches:
        cur.execute("INSERT INTO anon_linux_directory (original, id_category) VALUES (%s, 12)", [single_directory])
    conn.commit()
    cur.close()
    conn.close()
    return "Directory values successfully added to the database!"
# @app.route('/json_domain')
# def json_domain():
#  with open("files/example.json", "r") as file:
#     fileData = file.read()
#     jsonData = json.loads(fileData)
#     metavalues=[]
#     try:
#      metavalues.append(jsonData["client.domain"])
#     except KeyError:
#      print('No such value.')
#     try:
#      metavalues.append(jsonData["client.registrated_domain"])
#     except KeyError:
#      print('No such value.')
#      try:
#          metavalues.append(jsonData["destination.domain"])
#      except KeyError:
#          print('No such value.')
#      try:
#          metavalues.append(jsonData["destination.registrated_domain"])
#      except KeyError:
#          print('No such value.')
#     try:
#         metavalues.append(jsonData["server.domain"])
#     except KeyError:
#         print('No such value.')
#     try:
#         metavalues.append(jsonData["source.domain"])
#     except KeyError:
#         print('No such value.')
#     try:
#         metavalues.append(jsonData["source.registrated_domain"])
#     except KeyError:
#         print('No such value.')
#     try:
#         metavalues.append(jsonData["url.domain"])
#     except KeyError:
#         print('No such value.')
#     try:
#         metavalues.append(jsonData["user.domain"])
#     except KeyError:
#         print('No such value.')
#  return metavalues
#
#
# @app.route('/json_dom')
# def json_dom():
#     with open("files/windows-log-regina.json", "r") as file:
#         fileData = file.read()
#         jsonData = json.loads(fileData)
#
#     keys = [
#         "client.domain",
#         "client.registrated_domain",
#         "destination.domain",
#         "destination.registrated_domain",
#         "server.domain",
#         "source.domain",
#         "source.registrated_domain",
#         "url.domain",
#         "user.domain"
#     ]
#
#     metavalues = [jsonData.get(key, 'No such value.') for key in keys]
#
#     return metavalues
# @app.route('/json_email')
# def json_email():
#  with open("files/example.json", "r") as file:
#     fileData = file.read()
#     jsonData = json.loads(fileData)
#     metavalues=[]
#     try:
#      metavalues.append(jsonData["email.bcc.address"])
#     except KeyError:
#      print('No such value.')
#     try:
#         metavalues.append(jsonData["email.cc.address"])
#     except KeyError:
#         print('No such value.')
#     try:
#         metavalues.append(jsonData["email.from.address"])
#     except KeyError:
#         print('No such value.')
#     try:
#         metavalues.append(jsonData["email.reply_to.address"])
#     except KeyError:
#         print('No such value.')
#     try:
#         metavalues.append(jsonData["email.sender.address"])
#     except KeyError:
#         print('No such value.')
#     try:
#         metavalues.append(jsonData["email.to.address"])
#     except KeyError:
#         print('No such value.')
#     try:
#         metavalues.append(jsonData["threat.enrichments.indicator.email.address"])
#     except KeyError:
#         print('No such value.')
#     try:
#         metavalues.append(jsonData["threat.indicator.email.address"])
#     except KeyError:
#         print('No such value.')
#     try:
#         metavalues.append(jsonData["user.email"])
#     except KeyError:
#         print('No such value.')
#  return metavalues

# @app.route('/json_directory')
# def json_directory():
#  with open("files/example.json", "r") as file:
#     fileData = file.read()
#     jsonData = json.loads(fileData)
#     metavalues=[]
#     try:
#      metavalues.append(jsonData["file.directory"])
#     except KeyError:
#      print('No such value.')
#     try:
#      metavalues.append(jsonData["file.path"])
#     except KeyError:
#      print('No such value.')
#  return metavalues
# @app.route('/json_ip')
# def json_ip():
#  with open("files/example.json", "r") as file:
#     fileData = file.read()
#     jsonData = json.loads(fileData)
#     metavalues=[]
#     try:
#      metavalues.append(jsonData["client.ip"])
#     except KeyError:
#      print('No such value.')
#     try:
#      metavalues.append(jsonData["client.nat.ip"])
#     except KeyError:
#      print('No such value.')
#     try:
#      metavalues.append(jsonData["destination.ip"])
#     except KeyError:
#      print('No such value.')
#     try:
#      metavalues.append(jsonData["destination.nat.ip"])
#     except KeyError:
#      print('No such value.')
#     try:
#      metavalues.append(jsonData["host.ip"])
#     except KeyError:
#      print('No such value.')
#     try:
#      metavalues.append(jsonData["observer.ip"])
#     except KeyError:
#      print('No such value.')
#     try:
#      metavalues.append(jsonData["related.ip"])
#     except KeyError:
#      print('No such value.')
#     try:
#      metavalues.append(jsonData["server.ip"])
#     except KeyError:
#      print('No such value.')
#     try:
#      metavalues.append(jsonData["server.nat.ip"])
#     except KeyError:
#      print('No such value.')
#     try:
#      metavalues.append(jsonData["source.ip"])
#     except KeyError:
#      print('No such value.')
#     try:
#      metavalues.append(jsonData["source.nat.ip"])
#     except KeyError:
#      print('No such value.')
#     try:
#      metavalues.append(jsonData["threat.enrichments.indicator.ip"])
#     except KeyError:
#      print('No such value.')
#     try:
#      metavalues.append(jsonData["threat.indicator.ip"])
#     except KeyError:
#      print('No such value.')
#
#  return metavalues
# @app.route('/json')
# def get_ip_values():
#     with open("files/windows-log-regina.json", "r") as file:
#         jsonData = json.load(file)
#         metavalues = [
#             jsonData.get("ip"),
#             jsonData.get("client.ip"),
#             jsonData.get("client.nat.ip"),
#             jsonData.get("destination.ip"),
#             jsonData.get("destination.nat.ip"),
#             jsonData.get("host.ip"),
#             jsonData.get("observer.ip"),
#             jsonData.get("related.ip"),
#             jsonData.get("server.ip"),
#             jsonData.get("server.nat.ip"),
#             jsonData.get("source.ip"),
#             jsonData.get("source.nat.ip"),
#             jsonData.get("threat.enrichments.indicator.ip"),
#             jsonData.get("threat.indicator.ip")
#         ]
#         return [ip for ip in metavalues if ip is not None]



if __name__ == '__main__':
    app.run(debug=True)




