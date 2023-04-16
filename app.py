
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.utils import secure_filename

import config
from functions import*
from time import perf_counter
import json
import ipaddress
from config import*


app = Flask(__name__)
UPLOAD_FOLDER = os.path.abspath("uploads")

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config.from_pyfile('config.py')

@app.route('/singlecategory')
def home():
    return render_template('singlecat.html')

@app.route('/singlecategory/anonymize', methods=['POST'])
def anonymize():
    file = request.files['file']  # Get the uploaded file from the form
    if file.filename.endswith(('.json', '.log')):  # Check if file has .json or .log extension
        content = file.read().decode('utf-8')
        anon_content = ''
        for line in content.splitlines():
            if config.EMAIL:  # Check if EMAIL configuration variable is True
                anon_line = anonymize_email_line(line)
            elif config.IPV4:  # Check if IP configuration variable is True
                anon_line = anonymize_ipv4_line(line)
            elif config.IPV6:
                anon_line = anonymize_ipv6_line(line)
            elif config.LINKLOCAL:
                anon_line = anonymize_link_local_ipv6(line)
            elif config.DOMAIN:
                anon_line = anonymize_domain_line(line)
            elif config.MAC:
                anon_line = anonymize_mac_line(line)
            elif config.URL:
                anon_line = anonymize_url_line(line)
            elif config.WINDOWS_DIR:
                anon_line = anonymize_windows_line(line)

            else:
                anon_line = line
            anon_content += anon_line + '\n'

        # Save anonymized content to a file in "uploads" directory
        output_filename = 'anonymized_output.log' if file.filename.endswith('.log') else 'anonymized_output.json'
        output_path = os.path.join('uploads', output_filename)
        checkbox_state = request.form.get('checkbox')
        if checkbox_state == 'checked':
            empty_dictionaries()
        with open(output_path, 'w') as output_file:
            output_file.write(anon_content)

        return f'<pre>{anon_content}</pre>'
    else:
        return 'Invalid file format. Please upload a .json or .log file.'

# def allowed_file(filename):
#     return '.' in filename and \
#            filename.rsplit('.', 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]
# @app.route('/tmp', methods=['GET', 'POST'])
# def tmp_form():
#     if request.method == 'POST':
#         file = request.files['file']
#         if file and allowed_file(file.filename):
#             filename = secure_filename(file.filename)
#             return 'File uploaded successfully'
#         else:
#             return 'Invalid file type'
#     return render_template('result.html')

@app.route('/')
def upload_form():
    return render_template('upload.html')
@app.route('/upload/json')
def index():
    return render_template('json.html')

@app.route('/anonymized/json', methods=['POST'])
def json_file():
    if request.method == 'POST':
        file = request.files['jsonfile']
        if file.filename != '':
            file.save(secure_filename(file.filename))
            with open(file.filename) as f:
                data = json.load(f)
            checkbox_state = request.form.get('checkbox')
            if checkbox_state == 'checked':
                empty_dictionaries()
            elasticsearch = Elasticsearch()
            anonymized_data = anonymize_data(data, elasticsearch)
            return render_template('result.html', json_data=json.dumps(anonymized_data, indent=2))
    return "No file selected."


@app.route('/', methods=['POST'])
def upload_file():
    # Get the uploaded file from the request
    file = request.files['file']

    # Get the file extension
    file_extension = os.path.splitext(file.filename)[1]

    # Check the file extension and set the output file extension
    if file_extension == '.log':
        output_extension = '.log'
    else:
        # Return an error message if the file extension is not supported
        return 'Error: Unsupported file type.'

    # Perform anonymization and get the output
    function = complete_anonymization(file)

    # Set the output file name and path
    output_filename = os.path.splitext(file.filename)[0] + '_anonymized' + output_extension
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

    # Save the output to disk
    with open(output_path, 'w') as f:
        f.write(function)

    # Clear the global dictionaries if the checkbox is checked
    checkbox_state = request.form.get('checkbox')
    if checkbox_state == 'checked':
        empty_dictionaries()

    return '<pre>' + function + '</pre>'

def empty_dictionaries():
    clear_dicts(username_dictionary, organizations_dictionary, win_path_dictionary, linux_path_dictionary,
    name_dictionary, ip_dictionary, url_dictionary, ipv6_dictionary, mac_dictionary,
    email_dictionary, domains_dictionary)
    print(sys.getsizeof(ip_dictionary))
    return render_template('submit.html')


# @auth.verify_token
# def verify_token(token):
#     return token in app.config['TOKENS']
# @auth.verify_token
# def verify_token(token):
#     # token='abc'
#     if token in app.config['TOKENS']:
#         session['logged_in']=True
#         return True
#     return False
# def ip():
#     t1_start = perf_counter()
#     matches = regex_ipv4('files/waf.log') # calling function with the regex;
#     print_original(matches)#calling function for printing matches into console
#     t2_end = perf_counter()#function used for performance testing
#     print(t1_start)
#     print(t2_end)
#     return matches
# @app.route('/')
# def index():
#     return render_template('login.html')
# @app.route('/protected')
# @auth.login_required
# def protected():
#     return 'This page is protected'

# @app.route('/login', methods=['POST'])
# def login():
#     token = request.form['token']
#     if token in app.config['TOKENS']:
#         session['token'] = token
#         return redirect(url_for('upload_form'))
#     else:
#         return 'Invalid token'
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


if __name__ == '__main__':
    app.run(debug=True)




