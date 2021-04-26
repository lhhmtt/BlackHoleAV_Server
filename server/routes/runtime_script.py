import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import json
import requests
from threading import Thread
from queue import Queue
from colorama import Fore
import sys

sys.path.append('C:/Users/BlackHoleAV/BlackHoleAV_Server/server/routes')
import tool_convert
import malware_data_analysis
from pathlib import Path
from requests_toolbelt.multipart.encoder import MultipartEncoder

SERVER = "http://127.0.0.1:8000"
APIKEY = '3002c155ea8cfeaaa6627e5b1bf4385794e8ab4daba35e3888a594e061c62293'

#root = "C:/Users/asus/Desktop/Android Malware/"
root = "C:/Users/BlackHoleAV/BlackHoleAV_Server/uploads/"
# đường dẫn folder malware


# upload dùng api của mob
def upload(file1):
    """Upload File"""
    print(Fore.YELLOW + "Uploading file")
    print(file1)
    multipart_data = MultipartEncoder(
        fields={'file': (root + file1, open(root + file1, 'rb'), 'application/octet-stream')})
    headers = {'Content-Type': multipart_data.content_type, 'Authorization': APIKEY}
    response = requests.post(SERVER + '/api/v1/upload', data=multipart_data, headers=headers)
    return response.text


# scan dùng api mob
def scan(data):
    """Scan the file"""
    print("Scanning file")
    post_dict = json.loads(data)
    headers = {'Authorization': APIKEY}
    requests.post(SERVER + '/api/v1/scan', data=post_dict, headers=headers)


# gen ra json
def json_resp(data):
    """Generate JSON Report"""
    print("Generate JSON report")
    headers = {'Authorization': APIKEY}
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(SERVER + '/api/v1/report_json', data=data, headers=headers)
    return response.json()

def delete(data):
    """Delete Scan Result"""
    print("Deleting Scan")
    headers = {'Authorization': APIKEY}
    data = {"hash": json.loads(data)["hash"]}
    requests.post(SERVER + '/api/v1/delete_scan', data=data, headers=headers)
    print("delete done")

def returnDecision():
    decision = malware_data_analysis.RandomForest_250()
    return decision


class Watcher:
    DIRECTORY_TO_WATCH = root

    def __init__(self):
        self.observer = Observer()

    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, self.DIRECTORY_TO_WATCH, recursive=True)
        self.observer.start()
        try:
            while True:
                print("Watcher is running!!!!")
                time.sleep(5)
        except:
            self.observer.stop()
            print("Error")

        self.observer.join()
        print(event_handler)

class Handler(FileSystemEventHandler):

    @staticmethod
    def on_any_event(event):
        if event.is_directory:
            return None

        elif event.event_type == 'created':
            file = os.path.basename(event.src_path)
            a = Path(file).stem
            time.sleep(1)
            uploaded = upload(file)
            scan(uploaded)
            json1 = json_resp(uploaded)
            with open("C:/Users/BlackHoleAV/Desktop/response_json/" + a + ".json", 'w') as outfile:
                # tải json từ mob về và ném vào vào folder của mình
                json.dump(json1, outfile)
            print("Generate json : done")
            tool_convert.convert(event.src_path)
            print(returnDecision())
            delete(uploaded)
            print("done")
            return 1
            # Take any action here when a file is first created.
            #print "Received created event - %s." % event.src_path





if __name__ == '__main__':
    w = Watcher()
    w.run()
