import requests
import os.path
from pprint import pprint
from server.config import (VT_API_URL, VT_KEY)

class Virustotal:
    def __init__(self):
        self.headers_config = {
            "x-apikey": VT_KEY
        }

    # Retrieve information about a file
    def get_file_info(self, id):
        res = requests.get(f'{VT_API_URL}/files/{id}', headers=self.headers_config)
        return res.json()

    # Get information about the analysis
    def get_analysis_info(self, id):
        res = requests.get(f'{VT_API_URL}/analyses/{id}', headers=self.headers_config)
        return res.json()

    # Upload and analyse a file
    def file_analysis(self, files):
        res = requests.post(f'{VT_API_URL}/files', files = files, headers=self.headers_config)
        return res.json()

    # Get Url for upload big file
    def get_upload_url(self):
        res = requests.get(f'{VT_API_URL}/files/upload_url', headers=self.headers_config)
        return res.json()

    # Upload big file
    def big_file_upload(self, files, url):
        res = requests.post(f'{url}', files = files, headers=self.headers_config)
        return res.json()

    # Reanalyse a file already in VirusTotal
    def file_re_analysis(self, id):
        res = requests.post(f'{VT_API_URL}/files/{id}/analyse', headers=self.headers_config)
        return res.json()