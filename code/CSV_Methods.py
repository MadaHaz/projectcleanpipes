import csv

def writeToCSVMethod(mylist, fileName):
    with open(fileName, 'a', newline='') as myfile:
        wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
        wr.writerow(mylist)
