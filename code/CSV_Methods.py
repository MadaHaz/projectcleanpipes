import csv
import os

def writeToCSVMethod(mylist, fileName):
    if "c:" in fileName.lower():
        corrected_filename = fileName.replace('code/', '')
        corrected_filename = fileName.replace('\\code', '')
        with open(corrected_filename, 'a', newline='') as myfile:
            wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
            wr.writerow(mylist)
    else:
        corrected_filename = os.getcwd().replace('\\code', '')
        with open(corrected_filename + fileName, 'a', newline='') as myfile:
            wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
            wr.writerow(mylist)
