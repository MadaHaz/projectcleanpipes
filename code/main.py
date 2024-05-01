import requests
import urllib.request
from website_functions import *
import pydnsbl
import csv
from nslookup import Nslookup
from domain import Domain
from ISP_Domain_Results_Interpreter import ISP_Domain_Results_Interpreter
from ISP import ISP
import ipaddress
from CSV_Methods import *
import customtkinter as ctk
from tkinter import filedialog  

def getResolvedIPs(TupleList):
    IPAddresses = []
    for tup in TupleList:
        IPList = tup[1]
        if IPList:
            firstIP = IPList[0]
        else:
            firstIP = ''
        IPAddresses.append(firstIP)

    return IPAddresses


def WriteResultsList(domainList, writeFile):
    websiteList = []
    with open(domainList) as fp:
        Lines = fp.readlines()
    for line in Lines:
        websiteList.append(line.strip('\n'))

    ourIP = str(getIPAddress())

    #AARNFile =  open("Most_Visited.txt","w", encoding="utf-8")
    for item in websiteList:
        positionofWWW = item.find('://')

        if "http" in item:
            WebsiteNOHttp = item[positionofWWW+3:]
        else:
        #If http in domain name, change to + 3, if no http, change to +1
            WebsiteNOHttp = item[positionofWWW+1:]

        try:
            requestResults = requestWebsite(WebsiteNOHttp)
            responseCODE = requestResults.get('RespondeCode')
        except Exception as e:
            responseCODE = str(e)

        try:
            WebsiteNOHttpNoSlash = WebsiteNOHttp.replace('/',"")
            ResolvedIPs = getIPAddressOfDomain(WebsiteNOHttpNoSlash)
            IPString = ResolvedIPs[0]
            IPList = ResolvedIPs[1]
        except Exception as e:
            IPString = str(e)
            IPList = ['NaN','NaN','NaN','NaN','NaN','NaN','NaN','NaN','NaN','NaN','NaN','NaN']

        responseCODE = responseCODE.replace(',',';')

        if 'www.' == WebsiteNOHttp[0:4]:
            WebsiteNoWWWNoSlash = WebsiteNOHttp[4:]
        else:
            WebsiteNoWWWNoSlash = WebsiteNOHttp
        if '/' == WebsiteNoWWWNoSlash[-1]:
            WebsiteNoWWWNoSlash = WebsiteNoWWWNoSlash[0:-1]

        hopList = scapyTracerouteWithSR(WebsiteNoWWWNoSlash)
        hopNumber = len(hopList)
        hopListSting = str(hopList).replace(',',';')

        DifferentDNSIPs = resolveIPFromDNS(WebsiteNoWWWNoSlash, listOfDNSs())

        DNSResolvedIPS = getResolvedIPs(DifferentDNSIPs)

        DNSIPResponseCodes = IPResponseCodes(DNSResolvedIPS)

        DifferentDNSIPSting = str(DifferentDNSIPs).replace(',',';')

        IpRequestResponseCodes = IPResponseCodes(IPList)

        IpRequestResponseCodesString = str(IpRequestResponseCodes).replace(",",';')

        resultsList = [item, responseCODE, IPString, IpRequestResponseCodesString, hopNumber, hopListSting, DNSResolvedIPS[0], DNSResolvedIPS[1], DNSResolvedIPS[2],
        DNSResolvedIPS[3], DNSResolvedIPS[4],DNSIPResponseCodes[0],DNSIPResponseCodes[1],DNSIPResponseCodes[2],DNSIPResponseCodes[3], DNSIPResponseCodes[4]]

        writeToCSVMethod(resultsList, writeFile)
        #AARNFile.write(item + "," + str(responseCODE) +"," +IP + "\n")

    AARNFile.close()


def checkErrorCodeOfOtherDNS(tupleList):
    for tupl in tupleList:
        ip = tupl[0]


def checkIP():
    p=sr1(IP(dst='140.32.113.3')/ICMP())
    if p:
        p.show()


def writeObjectToCSV(obj, writeFile):
    resultsList = [obj.domain, obj.responseCode, obj.ISP_DNS, obj.ISP_DNS_IPS, obj.ISP_IP_Response_Code ,obj.Traceroute , obj.Hops_to_Domain ,  obj.AARC_DNS_IPs, obj.Optus_DNS_IPs, obj.Google_DNS, obj.Cloudflare_DNS, obj.AARC_DNS_Response_Code, obj.Optus_DNS_Response_Code, obj.Google_DNS_Response_Code, obj.Cloudflare_DNS_Response_Code,
    obj.domainBlockPage, obj.AARC_DNS_Block_Page, obj.Optus_DNS_Block_Page, obj.Google_DNS_Block_Page, obj.Cloudflare_DNS_Block_Page, obj.domainCloudFlareBlockPage, obj.AARC_DNS_Cloudflare_Block_Page, obj.Optus_DNS_Cloudflare_Block_Page, obj.Google_DNS_Cloudflare_Block_Page, obj.Cloudflare_DNS_Cloudflare_Block_Page, obj.Default_DNS_Block_Page, obj.Default_DNS_Cloudflare_Block_Page]

    writeToCSVMethod(resultsList, writeFile)


def CalculateListOfDomains(openFile, writeFile):
    websiteList = []
    with open(openFile) as fp:
        Lines = fp.readlines()
    for line in Lines:
        websiteList.append(line.strip('\n'))

    ourIP = str(getIPAddress())

    #AARNFile =  open("Most_Visited.txt","w", encoding="utf-8")
    for item in websiteList:
        domain = item
        domainStripped = stripDomainName(domain)
        WebsiteNOHttp = domainStripped.get('WebsiteNOHttp')
        WebsiteNOHttpNoSlash  = domainStripped.get('WebsiteNOHttpNoSlash')
        WebsiteNoHttpNoWWWNoSlash  = domainStripped.get('WebsiteNoHttpNoWWWNoSlash')

        print(item)
        obj = Domain(domain = domain,domainNoHTTP = WebsiteNOHttp,domainNoHTTPNoSlash = WebsiteNOHttpNoSlash, domainNoHTTPNoSlashNoWWW =  WebsiteNoHttpNoWWWNoSlash)
        writeObjectToCSV(obj, writeFile)


def readCSVToDomain(file_names):
    results_files = file_names
    ISP_list = []

    for file in results_files:
        with open(os.path.join('../results',file)) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            line_count = 0
            domainDict = {}

            for row in csv_reader:
                if line_count == 0:
                    line_count += 1
                else:
                    name = 'domain_{}'.format(stripDomainName(row[0]).get('WebsiteNoHttpNoWWWNoSlash').replace('.',""))
                    print("ISP: "+str(file)+ " DOMAIN: "+str(name))
                    domainDict[name] = Domain(domain = row[0],
                    responseCode= row[1], ISP_DNS = row[2], ISP_DNS_IPS=row[3].strip('][').replace('\'','').replace(' ','').split(','), ISP_IP_Response_Code=row[4].strip('][').split(', '), Traceroute=row[5].strip('][').split(', '), Hops_to_Domain=row[6], AARC_DNS_IPs=row[7].strip('][').split(', '),
                    Optus_DNS_IPs=row[8].strip('][').split(', '), Google_DNS=row[9].strip('][').split(', '), Cloudflare_DNS=row[10].strip('][').split(', '),AARC_DNS_Response_Code=row[11].strip('][').split(', '),
                    Optus_DNS_Response_Code=row[12].strip('][').split(', '),Google_DNS_Response_Code=row[13].strip('][').split(', '), Cloudflare_DNS_Response_Code=row[14].strip('][').split(', '),Resolved_IPs ="Read from CSV",
                    Response_Code_Different_DNS_List ="Read from CSV",
                    Block_Page_Different_DNS_List ="Read from CSV",domainBlockPage=row[15], AARC_DNS_Block_Page = row[16].strip('][').replace('\'','').split(', '), Optus_DNS_Block_Page = row[17].strip('][').replace('\'','').split(', '), Google_DNS_Block_Page = row[18].strip('][').replace('\'','').replace('\'','').split(', '), Cloudflare_DNS_Block_Page = row[19].strip('][').replace('\'','').split(', '), Cloudflare_Block_Page_Different_DNS_List = "Read from CSV",domainCloudFlareBlockPage = row[20],
                    AARC_DNS_Cloudflare_Block_Page = row[21].strip('][').replace('\'','').split(', '), Optus_DNS_Cloudflare_Block_Page = row[22].strip('][').replace('\'','').split(', '), Google_DNS_Cloudflare_Block_Page = row[23].strip('][').replace('\'','').split(', '), Cloudflare_DNS_Cloudflare_Block_Page = row[24].strip('][').replace('\'','').split(', '), Default_DNS_Block_Page = row[25].strip('][').replace('\'','').replace(' ','').split(','), Default_DNS_Cloudflare_Block_Page = row[26].strip('][').replace('\'','').replace(' ','').split(','))

                    line_count += 1

            new_ISP = ISP("ISP_{}".format(file), domainDict)
            ISP_list.append(new_ISP)

            domainDict = {}
            new_ISP  = None

    return ISP_list


def insertStrInToDict(dic, key, value):
    if key not in dic:
        dic[key] = [value]
    else:
        dic[key] = dic[key] + [value]


def insertListInToDict(dic, key, value):
    if key not in dic:
        dic[key] = value
    else:
        dic[key] = dic[key] + value


def getAllResponseCodes(ISP_List):
    domain_response_codes = {}
    default_DNS_response_codes = {}
    public_DNS_response_codes = {}
    for isp in ISP_List:
        for dom in isp.domains:
            insertStrInToDict(domain_response_codes, dom, isp.domains.get(dom).responseCode)
            insertListInToDict(default_DNS_response_codes, dom, isp.domains.get(dom).ISP_IP_Response_Code)
            insertListInToDict(public_DNS_response_codes, dom, isp.domains.get(dom).Google_DNS_Response_Code + isp.domains.get(dom).Cloudflare_DNS_Response_Code)

    return {'domain_response_codes':domain_response_codes, 'default_DNS_response_codes':default_DNS_response_codes ,'public_DNS_response_codes':public_DNS_response_codes}


def List_Of_Domains(domainFile):
    domain_list = []
    with open('../data/' + domainFile) as fp:
        Lines = fp.readlines()
    for line in Lines:
        line = line.rstrip("\n")
        name = 'domain_{}'.format(stripDomainName(line).get('WebsiteNoHttpNoWWWNoSlash').replace('.',"").rstrip("\n"))
        domain_list.append(name)
    return domain_list


def writeCollatedResults(ISP_List,allResponseCodes):
    domain_response_codes = allResponseCodes.get('domain_response_codes')
    default_DNS_response_codes = allResponseCodes.get('default_DNS_response_codes')
    public_DNS_response_codes = allResponseCodes.get('public_DNS_response_codes')

    for isp in ISP_List:
        #new_Results = ISP_Domain_Results_Interpreter("hey", isp)
        #new_Results.get_domains()

        #ALL_Other_ISPs = ISP_List
        #ALL_Other_ISPs.remove(isp)

        # Change the last part of this function to whichever file was used to create the data.
        New_ISP_Domain_Results_Interpreter = ISP_Domain_Results_Interpreter(isp.name,isp,ISP_List,domain_response_codes,default_DNS_response_codes,public_DNS_response_codes, List_Of_Domains("30BannedSites_2020.txt"))
        New_ISP_Domain_Results_Interpreter.writeResults()
        #ALL_Other_ISPs.append(isp)


def interpretResults(interpret_files):
    ISP_LIST = readCSVToDomain(interpret_files)

    allResponseCodes = getAllResponseCodes(ISP_LIST)
    writeCollatedResults(ISP_LIST,allResponseCodes)


def runGUI():
    # SETUP TKINTER 
    ctk.set_appearance_mode("light") # Modes: "system" (default), "dark", "light"
    ctk.set_default_color_theme("blue") # Themes: "blue" (default), "green", "dark-blue"
    app = ctk.CTk()
    app.geometry("400x300") # Set the size.
    app.title('Clean Pipes GUI') # Set the name.

    # Create the tab view
    tab_view = ctk.CTkTabview(app)
    tab_view.pack(padx=20, pady=20)

    # COLLECTION TAB
    # Create the first tab.
    CollectionTab = tab_view.add("Collection")
    # Create label for ISP Name field.
    label_ISPName = ctk.CTkLabel(master=CollectionTab, text="ISP Name:")
    label_ISPName.pack()
    # Create input field for ISP Name.
    input_ISPName = ctk.CTkEntry(master=CollectionTab, width=200)
    input_ISPName.pack()
    # Import files.
    def handle_file_selection():
        # Open file selector, looking for text files.
        filename = filedialog.askopenfilename(title="Select a file", filetypes=[("Text files", "*.txt")])

        # Update field with selection.
        if filename:
            input_siteList.delete(0, "end") # Clear previous selection.
            input_siteList.insert(0, filename)
            print(filename)

    # Create label for file selection field.
    label_siteList = ctk.CTkLabel(master=CollectionTab, text="Select File:")
    label_siteList.pack()
    # Create input field for site list file.
    input_siteList = ctk.CTkEntry(master=CollectionTab, width=200, state="readonly")  # Set as read-only
    input_siteList.pack()
    # Create button to start file selection.
    button_siteList = ctk.CTkButton(master=CollectionTab, text="Browse", command=handle_file_selection)
    button_siteList.pack()

    # INTERPRET TAB
    # Create the second tab
    InterpretTab = tab_view.add("Interpret")
    # Create elements for tab 2
    label2 = ctk.CTkLabel(master=InterpretTab, text="This is tab 2")
    label2.pack(pady=10)
    button2 = ctk.CTkButton(master=InterpretTab, text="Button in Tab 2")
    button2.pack()

    # Start the Tkinter event loop.
    app.mainloop();


def main():
    print("STARTED")
    runGUI()

    # Uncomment this to interpret results. Dev Testing.
    # interpret_files = ['Optus_25Mar.csv','AARC_12Apr.csv']
    # interpretResults(interpret_files)

    # Uncomment this for data collection. Dev Testing.
    # CalculateListOfDomains("../data/CopyRight_Telstra.txt","../results/Optus_25Mar.csv")

    # Collect data on 30 Banned Sites (BS).
    # Output file format is BS_ISPNAME_DAYMONTH_YEAR.csv, example is, BS_AussieBroadband_25Apr_2024.csv
    # CalculateListOfDomains("../data/30BannedSites_2020.txt", "../results/BS_AussieBroadband_25Apr_2024.csv");

    # Collect data on 15 Top Sites (TS).
    # Output file format is TS_ISPNAME_DAYMONTH_YEAR.csv, example is, TS_AussieBroadband_25Apr_2024.csv
    # CalculateListOfDomains("../data/15MostVisitedSites_April_2024.txt", "../results/TS_AussieBroadband_25Apr_2024.csv");

    # Interpret the results.
    # Place the output files from the previous step here. Both BS and TS
    # IMPORTANT, Make sure to change the filename in line 267 to whichever file was used to make the results file you want to interpret.
    # Make sure there is only 1 file interpretted at a time.
    # LEAVE THIS FOR LATER.
    # interpret_files = ['BS_AussieBroadband_25Apr_2024.csv']
    # interpretResults(interpret_files);

    # Results are stored in ./results/collated_results_interpreted.csv
    # Change the name of that file before uploading them.
    # Format is, TYPE_ISPNAME_Collated_Results_Interpreted.csv, example is, TS_AussieBroadband_Collated_Results_Interpreted.csv






if __name__ == "__main__":
    main()

    # # SETUP TKINTER 
    # ctk.set_appearance_mode("light") # Modes: "system" (default), "dark", "light"
    # ctk.set_default_color_theme("blue") # Themes: "blue" (default), "green", "dark-blue"
    # root = ctk.CTk()
    # root.geometry("500x350") # Set the size.
    # root.title('Clean Pipes GUI') # Set the name.

    # # SETUP FRAME
    # frame = ctk.CTkFrame(master = root)
    # frame.pack(pady = 20, padx = 60, fill = "both", expand = True)

    # label = ctk.CTkLabel(master = frame, text = "IN PROGRESS", font = ("Roboto", 24))
    # label.pack(pady = 12, padx = 10)

    # # Start the Tkinter event loop.
    # root.mainloop();