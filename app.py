
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

import config
from functions import*
import json
from jsonfile import*
import metakeys_config
from regex import*
import ipaddress
from config import*


app = Flask(__name__)
UPLOAD_FOLDER = os.path.abspath("uploads")
configuration = metakeys_config.Elasticsearch
# configuration = metakeys_config.RSANetWitness
# configuration = metakeys_config.QRadar

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config.from_pyfile('config.py')

@app.route('/anonymize/singlecategory')
def home():
    return render_template('singlecat.html')

@app.route('/anonymize/singlecategory', methods=['POST'])
def anonymize():
    file = request.files['file']  # Get the uploaded file from the form
    checkbox_state = request.form.get('checkbox')
    if file.filename.endswith(('.log')):  # Check if file has .json or .log extension
        content = file.read().decode('utf-8')
        anon_content = ''
        for line in content.splitlines():
            if config.EMAIL:  # Check if EMAIL configuration variable is True
                line = Regex.anonymize_email_line(line)
            if config.IPV4:  # Check if IP configuration variable is True
                line = Regex.anonymize_ipv4_line(line)
            if config.IPV6:
                line = Regex.anonymize_ipv6_line(line)
            if config.LINKLOCAL:
                line = Regex.anonymize_linklocal_line(line)
            if config.DOMAIN:
                line = Regex.anonymize_domain_line(line)
            if config.MAC:
                line = Regex.anonymize_mac_line(line)
            if config.URL:
                line = Regex.anonymize_url_line(line)
            if config.WINDOWS_DIR:
                line = Regex.anonymize_windows_line(line)

            else:
                line = line
            anon_content += line + '\n'

        # Save anonymized content to a file in "uploads" directory
        output_filename = 'anonymized_output.log'
        output_path = os.path.join('uploads', output_filename)
        with open(output_path, 'w') as output_file:
            output_file.write(anon_content)
        if checkbox_state == 'checked':
            empty_dictionaries()
        return f'<pre>{anon_content}</pre>'
    elif file.filename.endswith(('.json')):
        if request.method == 'POST':
            file = request.files['file']
            if file.filename != '':
                file.save(secure_filename(file.filename))
                with open(file.filename) as f:
                    data = json.load(f)

                anonymized_data = Process.anonymize_data_single_category(data, configuration)
                if checkbox_state == 'checked':
                    empty_dictionaries()
                return anonymized_data
        return "No file selected."
    else:
        return 'Invalid file format. Please upload a .json or .log file.'

@app.route('/')
def upload_form():
    return render_template('upload.html')
@app.route('/anonymize/json')
def index():
    return render_template('json.html')

@app.route('/anonymize/json', methods=['POST'])
def json_file():
    if request.method == 'POST':
        file = request.files['jsonfile']
        if file.filename != '':
            file.save(secure_filename(file.filename))
            with open(file.filename) as f:
                data = json.load(f)
            checkbox_state = request.form.get('checkbox')

            anonymized_data = Process.anonymize_data(data, configuration)
            if checkbox_state == 'checked':
                empty_dictionaries()
            return anonymized_data
    return "No file selected."

# @app.route('/anonymize/json', methods=['POST'])
# def json_file():
#     if request.method == 'POST':
#         data = request.json
#         anonymized_data = anonymize_data(data, configuration)
#         return anonymized_data
#
#     return "No data received."


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
    function = Regex.complete_anonymization(file)

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
    Functions.clear_dicts()
    print(sys.getsizeof(Functions.ip_dictionary))
    return ' '


if __name__ == '__main__':
    app.run(debug=True)




