import csv
import os

def writeToCSVMethod(mylist, fileName):
    if "c:" in fileName.lower():
        with open(fileName, 'a', newline='') as myfile:
            wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
            wr.writerow(mylist)
    else:
        with open(os.getcwd() + fileName, 'a', newline='') as myfile:
            wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
            wr.writerow(mylist)
