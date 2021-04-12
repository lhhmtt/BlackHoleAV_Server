import os

from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "LHH"
cors = CORS(app)

from server.routes import *
