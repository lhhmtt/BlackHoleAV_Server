import os
import json
import sqlite3
import hashlib
import runtime_script
import sys



from server import app
from flask import Flask, flash, request, redirect, url_for, jsonify
from werkzeug.utils import secure_filename

from server.virustotal import *
from server.config import *
from server.utils.convert import *

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'apk'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

sys.path.append('C:/Users/BlackHoleAV/BlackHoleAV_Server/server/routes')

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
          filename = secure_filename(file.filename)
          FILE_PATH = os.path.join(app.config['UPLOAD_FOLDER'], filename)
          file.save(FILE_PATH)
          base_name = os.path.basename(FILE_PATH)
          files = {"file": (os.path.basename(FILE_PATH), open(os.path.abspath(FILE_PATH), "rb"))}
          file_size = int(convert_unit(os.path.getsize(FILE_PATH)))
          md5 = hashlib.md5(open(os.path.abspath(FILE_PATH), "rb").read()).hexdigest()
          conn = sqlite3.connect('./database/db.sqlite')
          cur = conn.cursor()
          cur.execute('''CREATE TABLE IF NOT EXISTS File (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, md5 TEXT, status TEXT)''')
          cur.execute('SELECT status FROM File WHERE md5 = ? ', (md5,))
          row = cur.fetchone()
          if(row is not None):
            if (' '.join(row) == "clean"):
              print(f"{base_name} is signature_clean ")   
              return jsonify( status = "clean" )
            elif (' '.join(row) == "malware"):
              print(f"{base_name} is signature_malware ")   
              return jsonify( status = "malware" )
          else:
            vt = Virustotal()
            response = []
            if(file_size < 30):
              response = vt.file_analysis(files)
            else:
              url_upload = vt.get_upload_url()
              if(url_upload['data'] != ''):
                response = vt.big_file_upload(files, url_upload['data'])
            if(response["data"]["id"]):
              info = vt.get_analysis_info(response["data"]["id"])
              if (info['data']['attributes']['stats']['malicious'] == 0):               
                if(runtime_script.returnDecision() == "malware"):
                    cur.execute('''INSERT INTO File (name, md5, status) VALUES (?,?,?)''', (filename, info['meta']['file_info']['md5'], 'malware'))
                    conn.commit()
                    print(f"{base_name} is behavior_malware ")
                    return jsonify( status = "malware" )
                else:
                    cur.execute('''INSERT INTO File (name, md5, status) VALUES (?,?,?)''', (filename, info['meta']['file_info']['md5'], 'clean'))
                    conn.commit()
                    print(f"{base_name} is behavior_clean ")
                    return jsonify( status = "clean" )
              else:
                cur.execute('''INSERT INTO File (name, md5, status) VALUES (?,?,?)''', (filename, info['meta']['file_info']['md5'], 'malware'))
                conn.commit()
                print(f"{base_name} is virustotal_malware ")
                return jsonify( status = "malware" )
        else:
          return jsonify( status = "unknown", description = "Only APK are allowed" )

    return '''
    '''
