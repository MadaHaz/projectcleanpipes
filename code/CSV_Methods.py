import csv
import os

def writeToCSVMethod(mylist, fileName):
    with open(os.getcwd() + fileName, 'a', newline='') as myfile:
        wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
        wr.writerow(mylist)
