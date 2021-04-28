import os
import json
import requests
from threading import Thread
from queue import Queue
from colorama import Fore
from pathlib import Path
import time


from requests_toolbelt.multipart.encoder import MultipartEncoder

SERVER = "http://127.0.0.1:8000"
APIKEY = '23a1c8c2afd4bb43f51c848c5df8e0d37052be827b76896dd4be1dcfe38b1d31'

#root = "C:/Users/asus/Desktop/Android Malware/"
root = "D:/malware4/"
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

q = Queue()
def start_all():
    while True:
        try:
            file = q.get()
            a = Path(file).stem
            print(f"jsonname={a}")
            uploaded = upload(file)
            scan(uploaded)
            time.sleep(2)
            json1 = json_resp(uploaded)
            with open("C:/Users/asus/Desktop/response_json/" + a + ".json", 'w') as outfile:
                #tải json từ mob về và ném vào vào folder của mình
                json.dump(json1, outfile)
            print("Generate json : done")
            print(f"Deleting {a}")
            delete(uploaded)
        except Exception:
            print(Fore.RED + "apk error: " + a)
            pass
        else:
            print("Done: " + str(file))
        q.task_done()

        
#thread để chạy ( nếu có con sever ngon thì chạy apk thoải mái)
def main():
    global q
    n_threads = 8
    # fill the queue with all the subdomains
    for file in os.listdir(root):
        q.put(file)

    for t in range(n_threads):
        # start all threads
        worker = Thread(target=start_all, args=())
        # daemon thread means a thread that will end when the main thread ends
        worker.daemon = True
        worker.start()


if __name__ == "__main__":
    main()
    q.join()
    print("final finish")

