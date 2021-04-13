import os
import json
import sqlite3

from server import app
from flask import Flask, flash, request, redirect, url_for, jsonify
from werkzeug.utils import secure_filename

from server.virustotal import *
from server.config import *

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'apk'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
          return jsonify( status = "unknowm", description = "No file" )
        file = request.files['file']
        if file and allowed_file(file.filename):
          vt = Virustotal()
          filename = secure_filename(file.filename)
          FILE_PATH = os.path.join(app.config['UPLOAD_FOLDER'], filename)
          file.save(FILE_PATH)
          files = {"file": (os.path.basename(FILE_PATH), open(os.path.abspath(FILE_PATH), "rb"))}
          url_upload = vt.get_upload_url()
          if(url_upload['data'] != ''):
            response = vt.big_file_upload(files, url_upload['data'])
            if(response["data"]["id"]):
              info = vt.get_analysis_info(response["data"]["id"])
              conn = sqlite3.connect('./database/db.sqlite')
              cur = conn.cursor()
              cur.execute('''CREATE TABLE IF NOT EXISTS File (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, md5 TEXT, status TEXT)''')
              cur.execute('SELECT status FROM File WHERE md5 = ? ', (info['meta']['file_info']['md5'],))
              row = cur.fetchone()
              if(row is not None):
                if (' '.join(row) == "clean"):
                  return jsonify( status = "clean" )
                if (' '.join(row) == "malware"):
                  return jsonify( status = "malware" )
              else:
                if (info['data']['attributes']['stats']['malicious'] == 0):
                  cur.execute('''INSERT INTO File (name, md5, status) VALUES (?,?,?)''', (filename, info['meta']['file_info']['md5'], 'clean'))
                  conn.commit()
                  return jsonify( status = "clean" )
                else:
                  cur.execute('''INSERT INTO File (name, md5, status) VALUES (?,?,?)''', (filename, info['meta']['file_info']['md5'], 'malware'))
                  conn.commit()
                  return jsonify( status = "malware" )
        else:
          return jsonify( status = "unknown", description = "Only APK are allowed" )

    return '''
    '''