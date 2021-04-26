import os
import glob
import re
import csv
import json
import array as arr


def convert(file):
    path = "C:/Users/BlackHoleAV/Desktop/response_json"
    # x=os.listdir(os.path.expanduser(path))
    # print(x)
    files_path = os.path.join(path, '*.json')
    #print(files_path)
    files = sorted(glob.iglob(files_path), key=os.path.getctime, reverse=True)
    #print(files)

    path_last = str(files[0])
   # print(path_last)

    read_json = open(path_last)
    data_json = json.load(read_json)
    read_csv = open('C:/Users/BlackHoleAV/Desktop/Tool_convert/Input.csv')
    data_csv = csv.reader(read_csv)
    write_csv = open('C:/Users/BlackHoleAV/Desktop/Tool_convert/output_real.csv', 'a', newline='')
    writer = csv.writer(write_csv, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    List_csv_output = []
    List_csv_input = []

    for row in data_csv:
        row = str(row)
        row = row.replace("'", "")
        row = row.replace("[", "")
        row = row.replace("]", "")
        List_csv_input.append(row)

    data_json_string = str(data_json)

    for i in List_csv_input:
        i = str(i)
        if re.search(i, data_json_string):
            List_csv_output.append('1')
        else:
            List_csv_output.append('0')

    writer.writerow(List_csv_output)

    read_json.close()
