import time
import json
import requests
from colorama import Fore
import sys
sys.path.append('C:/Users/BlackHoleAV/BlackHoleAV_Server/server/routes')
import tool_convert
import malware_data_analysis
from requests_toolbelt.multipart.encoder import MultipartEncoder

SERVER = "http://127.0.0.1:8000"
APIKEY = '3002c155ea8cfeaaa6627e5b1bf4385794e8ab4daba35e3888a594e061c62293'

#root = "C:/Users/asus/Desktop/Android Malware/"
root = "C:/Users/BlackHoleAV/BlackHoleAV_Server/uploads/"
# đường dẫn folder malware


# upload dùng api của mob


def upload(file1):
    """Upload File"""
    print(f"Uploading file {file1}")
    multipart_data = MultipartEncoder(
        fields={'file': (root + file1, open(root + file1, 'rb'), 'application/octet-stream')})
    headers = {'Content-Type': multipart_data.content_type, 'Authorization': APIKEY}
    response = requests.post(SERVER + '/api/v1/upload', data=multipart_data, headers=headers)
    return response.text


# scan dùng api mob
def scan(data,name):
    """Scan the file"""
    print(f"Scanning file {name}")
    post_dict = json.loads(data)
    headers = {'Authorization': APIKEY}
    requests.post(SERVER + '/api/v1/scan', data=post_dict, headers=headers)


# gen ra json
def json_resp(data,name):
    print(f"Generate JSON report {name}")
    headers = {'Authorization': APIKEY}
    print(data)
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(SERVER + '/api/v1/report_json', data=data, headers=headers)
    return response.json()


def delete(data,name):
    """Delete Scan Result"""
    print(f"Deleting Scan {name}")
    headers = {'Authorization': APIKEY}
    data = {"hash": json.loads(data)["hash"]}
    requests.post(SERVER + '/api/v1/delete_scan', data=data, headers=headers)
    print("Delete done")


def returnDecision(base_name):
    time.sleep(1)
    uploaded = upload(base_name)
    scan(uploaded,base_name)
    json1 = json_resp(uploaded,base_name)
    with open("C:/Users/BlackHoleAV/Desktop/response_json/" + base_name + ".json", 'w') as outfile:
        json.dump(json1, outfile)
    print("Generate json : done")
    tool_convert.convert()
    delete(uploaded,base_name)
    result = malware_data_analysis.RandomForest_250()
    print("Final done")
    return result


