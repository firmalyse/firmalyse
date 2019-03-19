# Main app

from flask import Flask
app = Flask(__name__)

# Routes 
@app.route('/')
def homepage():
    return "Hello bananas"

# Run the server directly (python firmalyse.py)
if (__name__ == '__main__'):
    app.run()