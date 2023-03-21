
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import psycopg2
from pip._internal.network import auth
from flask_httpauth import HTTPTokenAuth
from functions import*
from time import perf_counter
import json
import ipaddress
from config import*
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)


app.config.from_pyfile('config.py')
auth = HTTPTokenAuth(scheme='Bearer')
app.secret_key = 'your_secret_key'
# def db_connection():#connection to DB using psycopg2 library
#     conn = psycopg2.connect(database="thesis",
#                             host="localhost",
#                             user="xyz",#zmenit
#                             password="xyz",
#                             port=5432
#                             )
    # return conn
# @app.route('/anon')
# def anon():
#     return complete_anonymization("singlelog.log")
@app.route('/json')
def json_form():
    return render_template('json.html')
@app.route('/json', methods=['POST'])
@auth.login_required
def handle_json():
    f = request.files['file']
    data = f.read()
    json_data = json.loads(data)
    return json_data

# @app.route('/json', methods=['POST'])
# def json():
#     logs=request.json
#     return logs
@app.route('/tmp')
def tmp_form():
    return render_template('tmp.html')

@app.route('/upload')
def upload_form():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])

def upload_file():
    # Get the uploaded file from the request
    file = request.files['file']

    # Save the file to disk
    #file.save('C:\\Users\\Asus\\Desktop\\zadania\\datasets\\an.log')

    # Return a response to the client
    return complete_anonymization(file)


# @app.route('/settings')
# def dictionaries_settings():
#     return render_template ("settings.html")

@app.route('/settings')
@auth.verify_token
def empty_dictionaries():
    clear_dicts(username_dictionary, organizations_dictionary, win_path_dictionary, linux_path_dictionary,
    name_dictionary, ip_dictionary, url_dictionary, ipv6_dictionary, mac_dictionary,
    email_dictionary, domains_dictionary)
    print(sys.getsizeof(ip_dictionary))
    return render_template('submit.html')

def allowed_file(filename):
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]
# @auth.verify_token
# def verify_token(token):
#     return token in app.config['TOKENS']
@auth.verify_token
def verify_token(token):
    # token='abc'
    if token in app.config['TOKENS']:
        session['logged_in']=True
        return True
    return False
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
    return render_template('login.html')
# @app.route('/protected')
# @auth.login_required
# def protected():
#     return 'This page is protected'

@app.route('/login', methods=['POST'])
def login():
    token = request.form['token']
    if token in app.config['TOKENS']:
        session['token'] = token
        return redirect(url_for('upload_form'))
    else:
        return 'Invalid token'
# @app.route('/')
# # def index():
# #     return render_template("index.html")
# @auth.login_required
# def index1():
#     return "Hello, {}!".format(auth.current_user())
# @app.route('/ipv4')
# def ipv4():
#     # matches = ip()
#     # anonymized = []
#     #
#     # for addr in matches:
#     #         ipaddr = str(ipaddress.ip_address(addr))
#     #         anonymized.append(str(anonymize_ip(ipaddr)))
#     return regex_ipv4('files/waf.log')
#
#
# @app.route('/ipv6')
# def ipv6():
#     return regex_ipv6('files/linux.log')
# @app.route('/mail')
# def mail():
#     matches=email()
#     anonymized=[]
#     for address in matches:
#         emailadd=address
#         anonymized.append(anonymize_email(emailadd))
#     return anonymized
#
# def email():
#     t1_start = perf_counter()
#     matches = regex_email("singlelog.log")
#     print_original(matches)
#     t2_end = perf_counter()
#     print(t1_start)
#     print(t2_end)
#     return matches
# @app.route('/mac_addr')
# def mac_addr():
#     matches=mac_address()
#     anonymized=[]
#     for address in matches:
#         macadd=address
#         anonymized.append(anonymize_mac(macadd))
#     return anonymized
#
# def mac_address():
#     t1_start = perf_counter()
#     matches = regex_mac("files/fortinet.log")
#     print_original(matches)
#     t2_end = perf_counter()
#     print(t1_start)
#     print(t2_end)
#     return matches
#
#
# @app.route('/linux-directory')
# def linux_directory():
#     matches = regex_linux_directory("files/linux.log")
#     print_original(matches)
#     return matches
# @app.route('/windows-directory')
# def windows_directory():
#     t1_start = perf_counter()
#     matches = regex_windows_directory("files/windows.log")
#     print_original(matches)
#     t2_end = perf_counter()
#     print(t1_start)
#     print(t2_end)
    # return matches
# @app.route('/findall')
# def findall():
#     windows_directory()
#     mac_address()
#     email()
#     ip()
#     return "Check your console."
# @app.route('/ipdb')#function for filling the database
# def ipdb():
#         matches = ip()
#         conn = db_connection()
#         cur = conn.cursor()
#         for singleIP in matches: #every single match is stored in database
#             cur.execute("INSERT INTO anon_ip (original, id_category) VALUES (%s, 1)", [singleIP])#the id_category refers to the category of sensitive data
#         conn.commit()
#         cur.close()
#         conn.close()
#         return "IP address values successfully added to the database!"
# @app.route('/emaildb')
# def emaildb():
#     matches = email()
#     conn = db_connection()
#     cur = conn.cursor()
#     for single_email in matches:
#         cur.execute("INSERT INTO anon_email (original, id_category) VALUES (%s, 5)", [single_email])
#     conn.commit()
#     cur.close()
#     conn.close()
#     return "Email values successfully added to the database!"
# @app.route('/macdb')
# def macdb():
#     matches = mac_address()
#     conn = db_connection()
#     cur = conn.cursor()
#     for singleMAC in matches:
#         cur.execute("INSERT INTO anon_mac (original, id_category) VALUES (%s, 2)", [singleMAC])
#     conn.commit()
#     cur.close()
#     conn.close()
#     return "MAC address values successfully added to the database!"
# @app.route('/directorydb')
# def directorydb():
#     matches = windows_directory()
#     conn = db_connection()
#     cur = conn.cursor()
#     for single_directory in matches:
#         cur.execute("INSERT INTO anon_windows_directory (original, id_category) VALUES (%s, 13)", [single_directory])
#     conn.commit()
#     cur.close()
#     conn.close()
#     return "Directory values successfully added to the database!"
# @app.route('/directorylinux')
# def directory_linux_db():
#     matches = linux_directory()
#     conn = db_connection()
#     cur = conn.cursor()
#     for single_directory in matches:
#         cur.execute("INSERT INTO anon_linux_directory (original, id_category) VALUES (%s, 12)", [single_directory])
#     conn.commit()
#     cur.close()
#     conn.close()
#     return "Directory values successfully added to the database!"


if __name__ == '__main__':
    app.run(debug=True)




