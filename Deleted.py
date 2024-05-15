# main.py
"""
import requests
import urllib.request
import pydnsbl
import ipaddress

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
            IPList = [
                'NaN','NaN','NaN','NaN',
                'NaN','NaN','NaN','NaN',
                'NaN','NaN','NaN','NaN'
            ]
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
        IpRequestResponseCodesString = (
            str(IpRequestResponseCodes).replace(",", ';')
        )
        resultsList = [
            item, responseCODE, IPString, IpRequestResponseCodesString,
            hopNumber, hopListSting, DNSResolvedIPS[0], DNSResolvedIPS[1],
            DNSResolvedIPS[2], DNSResolvedIPS[3], DNSResolvedIPS[4],
            DNSIPResponseCodes[0],DNSIPResponseCodes[1],
            DNSIPResponseCodes[2],DNSIPResponseCodes[3], DNSIPResponseCodes[4]
        ]
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

def CalculateListOfDomains(openFile, writeFile):
    ourIP = str(getIPAddress())
    # AARNFile =  open("Most_Visited.txt","w", encoding="utf-8")
"""

# detect_blockpages.py

"""
from urllib.request import Request, urlopen
import requests
from bs4 import BeautifulSoup
from bs4.element import Comment

def tag_visible(element):
    if element.parent.name in [
        'style', 'script', 'head', 'title', 'meta', '[document]'
    ]:
        return False
    if isinstance(element, Comment):
        return False
    return True


def text_from_html(body):
    soup = BeautifulSoup(body, 'html.parser')
    texts = soup.findAll(text=True)
    visible_texts = filter(tag_visible, texts)
    return u" ".join(t.strip() for t in visible_texts)
"""

# dnstraceroute
"""entire file"""

# pktInject.py
"""entire file"""

# synpy.py
"""entire file"""

# website_functions.py
"""
def getWebsitesFromText(text):
    textSplit = text.split()
    httpList = []
    for word in textSplit:
        if "http://" in word:
            httpList.append(word)
        if "https://" in word:
            httpList.append(word)
    return httpList

def getIPAddress():
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    return IPAddr

def CompareDNSResults(website):
    #this may be legacy...might use the change DNS in the future
    dns_resolver = dns.resolver.Resolver()
    DNSList = [dns_resolver.nameservers[0]]
    #DNSList = [dns_resolver.nameservers[0],'8.8.8.8','1.1.1.1']
    #cloudflare and google's DNS
    for DNS_Address in DNSList:
        ans, unans = traceroute(
            DNS_Address,
            l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname=website)),
            maxttl=15
            )
        #ans, unans = traceroute(
            DNS,
            l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname='google.com')),
            maxttl=15
            )
        for snd, _ in ans[TCP]:
            print(type(snd))


def DNSTraceroute(DNSServerAddress):
    ans, unans = traceroute(
        DNSServerAddress,
        l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname="cisco.com")),
        maxttl=15
    )
    ans.graph()
    return ans, unans


def getTraceRouteList(host):
    print("Traceroute", host)
    flag = True
    ttl=1
    hops = []
    while flag:
        ans, unans = sr(IP(dst=host,ttl=ttl)/ICMP(), timeout = 10)
        try:
            gotdata = ans.res[0][1]
        except IndexError:
            gotdata = 'null'
            hops = ['Error in Traceroute']
            return hops
        if ans.res[0][1].type == 0: # checking for  ICMP echo-reply
            flag = False
        else:
            hops.append(ans.res[0][1].src)
            # storing the src ip from ICMP error message
            ttl +=1
    i = 1
    for hop in hops:
        i+=1
    return hops

    def getIPSpecificDNS():
    #this is legacy code I think
    answer = sr1(
        (
            IP(dst='8.8.8.8')/
            UDP(dport=53)/
            DNS(rd=1, qd=DNSQR(qname='www.thepacketgeek.com'))
        ),
        verbose=0
    )

    def tryingDifferentDNS():
        my_resolver = dns.resolver.Resolver()
        # 8.8.8.8 is Google's public DNS server
        my_resolver.nameservers = ['8.8.8.8']
        answer = my_resolver.query('google.com')
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [ '8.8.8.8', '2001:4860:4860::8888',
                            '8.8.4.4', '2001:4860:4860::8844' ]
        r = res.query('example.org', 'a')

    def resolveIPFromDNS(hostname, DNSList):
        # soa_record = dns_query.soa_lookup(domain)
"""

# ISP.py

"""
from domain import Domain
from website_functions import *

class ISP:
    def get_domain(self, domain_code):
        return self.domains[domain_code]

    def return_class_variables(ISP):
        return(ISP.__dict__)

    def Find_DNS_Tampered_Domains(self):
        for domain in self.domains:
        # Converting string to list
             #res = (
                self.domains.get(domain)
                .ISP_IP_Response_Code.strip('][')
                .split(', ')
             )
             '''
             for item in self.domains.get(domain).ISP_IP_Response_Code:
                 print(item)
             if '200' in self.domains.get(domain).ISP_IP_Response_Code:
                 print("200 found...."+str(self.domains.get(domain).domain))
             for item in self.domains.get(domain).Traceroute:
                 print(item)
             print("DONE")
             '''
            # printing final result and its type
"""

# ISP_Domain_Results_Interpreter.py

"""
class ISP_Domain_Results_Interpreter:
    def get_domains(self):
        return self.ISP.domains

    def IPsInTwoLists(self, firstDNSIPList, secondDNSIPList):
        firstFoundInSecond = False
        for firstIP in firstDNSIPList:
            if firstIP in secondDNSIPList:
                firstFoundInSecond = True
                return True
        return False

    def DifferentResultsDetection(self, domain_name):
        see if response code and blockpages differ  from isp to isp by domain

    def IPBlockingDetection(self, domain_name):
         '''
        ListOfResponseCodes = {}
        ListOfBlockPages = {}
        for isp in self.All_ISPs:
            for dom in isp.domains:
                domain = isp.domains.get(dom)
                ListOfResponseCodes[isp.name] = domain.responseCode
        '''
        #does ip give a different response code or vary
        # in whether it returns a blockpage to other ISP's
        return True

    def DomainNameBlockingDetection(self):
        # does ip address reutrn 200 and is not a blockpage,
        # does domain not return 200
        #and does domain name return different response code and non blockpage
        return True

    def differenceInResponseCodes(self):
        #checks if default DNS Response code differ from public
        return 1


    def domainCodeDifferentIpCode(self):
        #
        return 1
"""

# Domain

"""
Class Domain:
     def ISPDNSResponseContradictionPublicDNSResponse(self):
        Public_Codes = self.getPublicDNSResponses()
        ISP_Codes = self.ISP_IP_Response_Code
        everyPubCodeIs200 = True
        everyISPCodeIs200 = True
        for pub_code in Public_Codes:
            if pub_code != '200':
                everyPubCodeIs200 = False

        for ISP_code in ISP_Codes:
            if ISP_code != '200':
                everyISPCodeIs200 = False

        if everyISPCodeIs200 == False and everyPubCodeIs200 == True:
            return True
        else:
            return False

    def myfunc(self):
        print("Hello my name is " + self.domain)

    def return_class_variables(Domain):
      return(Domain.__dict__)
"""

# !!!! Modications !!!!

# ISP_Domain_Results_Interpreter.py

"""
    #changed indentation to one back
    if __name__ == "__main__":
      a = Domain()
"""

# website_functions.py

"""
    # Changed all instances of TCP() and IP() to scapy.TCP() and scapy.IP()
    from scapy.all import *
    to
    import scapy.all as scapy
"""

# Main.py

"""
    # The previous change broke the os variable so I changed it to scapy.os
    def readCSVToDomain(file_names)
        with open(os.path.join('../results',file)) as csv_file:

    changed to

    def readCSVToDomain(file_names)
        with open(scapy.os.path.join('../results',file)) as csv_file:
"""
