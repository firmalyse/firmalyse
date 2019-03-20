# Main app

from flask import Flask, render_template, request
from analysis.AnalyzerMain import AnalysisMain
import os

app = Flask(__name__)

# Configurations for file upload
# TODO: is not working, plz make it work lul

UPLOAD_FOLDER = 'analysis_result'
MAX_FIRMWARE_SIZE = 50 * 1024 * 1024 # 50MB
# Check if analysis_result folder exists. If not, create folder.
if not os.path.exists(UPLOAD_FOLDER):
    print("creating folder")
    os.mkdir(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FIRMWARE_SIZE

# Routes 

@app.route('/')
def homepage():
    return "Hello bananas"

@app.route('/upload', methods=['GET', 'POST'])
def uploadFirmware():
    if request.method == 'GET':
        return render_template('upload.html')
    elif request.method == 'POST':
        firmwareBinary = request.files['firmware_binary']
        firmwareBinary.save(os.path.join(app.config['UPLOAD_FOLDER'], firmwareBinary.filename))
        analyzer = AnalysisMain(firmwareBinary)
        analyzer.start_analysis()
        return "analyzing firmware..." # temp


# Run the server directly (python firmalyse.py)
if (__name__ == '__main__'):
    app.run()