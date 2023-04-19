
from flask import Flask, render_template, request
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
                anon_line = Functions.anonymize_link_local_ipv6(line)
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
            if checkbox_state == 'checked':
                empty_dictionaries()

            anonymized_data = anonymize_data(data, configuration)
            # return render_template('result.html', json_data=json.dumps(anonymized_data, indent=2))
            return anonymized_data
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
    Functions.clear_dicts()
    print(sys.getsizeof(Functions.ip_dictionary))
    return ' '


if __name__ == '__main__':
    app.run(debug=True)




