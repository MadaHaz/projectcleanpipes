import requests
from bs4 import BeautifulSoup
from bs4.element import Comment
import socket
import scapy.all as scapy
import dns.resolver
from nslookup import Nslookup
import ipaddress
from detect_blockpages import detectBlockPage, detectCloudFlare


def str2bool(v):
    return v.lower() in ("true")


# tag_visible is passed an obj* and returns a boolean
def tag_visible(element):
    # element is an obj referencing HTML code
    # the structure of the obj is similar to the DOM
    # the elements parent name returns false if it is in the list
    if element.parent.name in [
            'style',
            'script',
            'head',
            'title',
            'meta',
            '[document]'
            ]:
        return False
    # isinstance(object, type) compares and obj and a type
    # Comment is a type that the obj will be if it is a HTML comment
    if isinstance(element, Comment):
        return False
    return True


# text_from_html takes a str of html
def text_from_html(body):
    # BeautifulSoup is a Python library for extracting HTML data
    # BeautifulSoup takes (HTML, arg_for_parser)
    # "html.parser" is one of the libraries parsers
    # soups returns an object that allows HTML to be accessed through methods
    soup = BeautifulSoup(body, 'html.parser')
    # findAll is a method that searches a HTML file to retrieve data that
    # matches the filters passed to the method like text=true
    # text is the body of HTML tags and text=true returns an tag body content
    # the list has a data type of <class bs4.element.ResultSet>
    # findAll and text arg may depreciated according to the documentation
    # newer method may be find_all and string instead of text
    texts = soup.findAll(text=True)
    print("!!!!!")
    # filter is a built in python keyword and takes a function and an iterable
    # iterables are filtered by the functions boolean return for each item
    # tag_visible returns false for HTML comments, and body content belonging
    # to certain parent elements like scripts, head and title
    # texts is an iterable as defined by its class
    # visible_texts filters out text not viewable by the user on a browser
    visible_texts = filter(tag_visible, texts)
    # u before a string denotes it is unicode string
    # each item in visible texts is iterated through
    # .strip() removes trailing and leading whitespace
    # " ".join() connects all stripped items with a space in between
    # the return value is a string of body text from the webpage
    return u" ".join(t.strip() for t in visible_texts)


# requestWebsite takes (str, boolean, boolean)
# website in format www.google.com/ with slash intact or absent
def requestWebsite(websiteURL, http, https):
    protocol = "This is broken"
    # conditionals assign protocol to http or https
    if (https is True):
        protocol = "https"
    if (http is True):
        protocol = "http"
    # if protocol is not http or https the query cannot be completed
    print("requesting: "+protocol+"://"+websiteURL)
    # requests is a python module that allows HTML requests to be sent
    # .get method takes (url, params, args)
    # the first value passed is the url being queried
    # auth is a parameter that takes a tuple and enables authentication
    # requests.get() returns a response object with all response data
    r = requests.get(protocol+"://"+websiteURL, auth=('user', 'pass'))
    print("WHY DO WE NOT GET HERE?")
    print("r: ")
    # r is the response object that has many methods
    # printing r prints <Response [200]> where "200" is the status code
    print(r)
    # results is a set but will become a dictionary containing response info
    results = {}
    # stores str of response status_code as ResponseCode in dictionary
    results['RespondeCode'] = str(r.status_code)
    # r.text returns content of HTML file -> <h1>Hello</h1> as a str
    # detectBlockPage is from detect_blockpages.py and returns a boolean
    # the HTML text input is searched for a blocked page response str
    results['BlockPage'] = detectBlockPage(
        # text_from_html returns filtered HTML page text as a string
        text_from_html(r.text)
        )
    # detectCloudFlare is from detect_blockpages.py and returns a boolean
    # the HTML text input is searched for CloudFlare response str
    results['CloudflareBlockPage'] = detectCloudFlare(
        # text_from_html returns filtered HTML page text as a string
        text_from_html(r.text)
        )
    return results


# getIPResponseCodeAndText takes (str)
def getIPResponseCodeAndText(IPAddress):
    # checks if IP is present
    if IPAddress == '' or IPAddress is None:
        return "NaN"
    try:
        # requests is a python module that allows HTML requests to be sent
        # .get method takes (url, params, args)
        # the first value passed is the url being queried
        # auth is a parameter that takes a tuple and enables authentication
        # requests.get() returns a response object with all response data
        r = requests.get('http://'+IPAddress)
        # r is the response object that has many methods
        # status_code is (int) and text is (string)
        # a dictionary of Response_Code and Visible_Text is returned
        return {
                'Response_Code': r.status_code,
                # text_from_html returns filtered HTML page text as a string
                'Visible_Text': text_from_html(r.text)
                }
    except Exception as e:
        # sets Response_Code as the error in str
        # a dictionary of Response_COde and Visible_Text is returned
        exce = str(e).replace(',', ";")
        return {'Response_Code': exce, 'Visible_Text': "N/A"}


# IPResponseCodesAndText takes (list[str])
def IPResponseCodesAndText(IPList):
    responseCodeList = []
    blockPageList = []
    cloudFlareBlockPageList = []
    print(IPList)
    # loop iterates through the list of IPs linked to the domain
    for IP in IPList:
        # response is a dictionary containing Response_Code and Visible_Text
        # Response_Code is a int or str if error
        # Visible_Text a string literal
        response = getIPResponseCodeAndText(IP)
        # type coercion into string for the responses
        print("IP: "+str(IP))
        print("Response: "+str(response))
        print("Response: "+str(response))
        # adds IP Response_Code to responseCodeList of type list[str]
        responseCodeList.append(response.get('Response_Code'))
        # detectBlockPage is from detect_blockpages.py and returns a boolean
        # the HTML text input is searched for a blocked page response str
        # adds boolean response from detectBlockPage to blockPageList
        blockPageList.append(
            # response.get('Visible_Text') returns filtered HTML text that
            # detectBlockPage() searches for common blocked page phrases
            detectBlockPage(response.get('Visible_Text'))
            )
        # cloudFlareBlockPage is from detect_blockpages.py and returns boolean
        # the HTML text input is searched for a blocked page response str
        # adds boolean return from detectCloudFlare to cloudFlareBlockPageList
        cloudFlareBlockPageList.append(
            # response.get('Visible_Text') returns filtered HTML text that
            # detectCloudFlare() searches for common blocked page phrases
            detectCloudFlare(response.get('Visible_Text'))
            )
    # returns {responseCodeList, blockPageList, cloudFlareBlockPageList}
    # of type {list[int], list[boolean], list[boolean]}
    return {
        'responseCodeList': responseCodeList,
        'blockPageList': blockPageList,
        'cloudFlareBlockPageList': cloudFlareBlockPageList
        }
    # "https://www.judgments.fedcourt.gov.au/judgments/Judgments/fca/single/2020/2020fca0769"


# getIPAddressOfDomain(str of domain without slash and http prefix)
# e.g "www.google.com"
# socket py docs suggest it may behave differently dependent on OS
def getIPAddressOfDomain(websiteURL):
    try:
        # socket allows access to BSD socket interface: a set of
        # standards that provides internet communications to an app
        # its an API using internet sockets.
        # the gethostbyname_ex() method translates a hostname to IPV4
        # it returns a tuple with (hostname, aliaslist, ipaddrlist)
        # the values are (str,list[str],list[str])
        result = socket.gethostbyname_ex(websiteURL)
        # second index is ipaddrlist -> list[str]
        IPAddressList = result[2]
        # the list[str] is made into a str and , is replaced by ;
        # ['apple','banana'] -> "['apple'; 'banana';]"
        IPaddressString = str(result[2]).replace(',', ";")
    except Exception as e:
        # because aliaslist is not used it is not addressed
        # IPaddressString is the error and IPAddressList must have val
        IPaddressString = str(e)
        IPaddressString.replace(',', ";")
        IPAddressList = ['NaN', 'NaN']
        # returns a tuple of str and list[str]
        # both are a list of IPs in different formats
    return IPaddressString, IPAddressList


# scapyTracerouteWithSR(str of domain without slash, www, http prefix)
# e.g google.com
def scapyTracerouteWithSR(domain):
    try:
        # scapy is a library for building and decoding packets with the
        # capability of being able to utilise and manipulate protocols
        # across multiple layers e.g. HTTP, TCP, and IP
        # the sr function is for sending packets and receiving answers
        # within scapy "/" is used to separate compositions between layers
        # in this instance a send receive is built with IP and TCP fields set
        # IP is setting dst to the domain str, ttl 1 to 25, id to a random int
        # and TCP is sending SYN flag Ox2 with traceroute built into request
        # gradually increasing ttl using range means upto 25 icmp responses
        # ans and unans are lists wrapped in an obj containing (query,response)
        # of packets that have been answered or unanswered respectively
        ans, unans = scapy.sr(
            scapy.IP(dst=domain, ttl=(1, 25), id=scapy.RandShort()) /
            scapy.TCP(flags=0x2), timeout=2
            )
    except Exception as e:
        # error is returned as str in a list
        return [str(e).replace(',', ";")]
    hops = []
    # the response portion of the list is taken from ans as rcv
    # meaning the responses to answered packets are being inspected
    for snd, rcv in ans:
        # the idea with traceroute is that ttl is gradually increased and ICMP
        # responses are returned until a server responding with TCP is found
        # counting ICMP responses until the TCP response gets us the hop count
        # the conditional adds rcv.src (the response IP src) to the hops list
        # if the payload is not of type scapy.TCP or if the last added IP in
        # hops is not the equal to rcv.src
        # rcv.src is a str
        if len(hops) > 0:
            if not isinstance(rcv.payload, scapy.TCP) or hops[-1] != rcv.src:
                hops.append(rcv.src)
        else:
            if not isinstance(rcv.payload, scapy.TCP):
                hops.append(rcv.src)
    # hops is list[str] of IP addresses gathered by ICMP responses en route
    return hops


# dns.resolver is a library that allows DNS operations and queries in py
# the Resolver() module uses DNS recursion with the DNS resolver
# provided by the host ISP or specified by the host system
def getMyDNS():
    # dns.resolver.Resolver() returns a class obj
    dns_resolver = dns.resolver.Resolver()
    # dns_resolver.nameservers is a list of nameserver str as IP or url
    # the docs are a bit confusing regarding the type of the response
    # apparently the response may be of type dns.nameserver.Nameserver
    return dns_resolver.nameservers[0]


# listOfDNSs() returns a list[str] of IPs comprised of common public DNS
# servers and the clients local DNS server
def listOfDNSs():
    # getMyDNS() returns the IP of one nameserver your clients DNS resolver
    # queries. Potentially there are more but the function returns one.
    MyDNS = getMyDNS()
    AARNet = "10.127.5.17"
    OptusDNS = "192.168.43.202"
    GoogleDNS = "8.8.8.8"
    Cloudflare = "1.1.1.1"
    DNSList = [MyDNS, AARNet, OptusDNS, GoogleDNS, Cloudflare]
    # returns list[str] of DNS nameserver IP addresses
    return DNSList


# resolveIPFromDNS(domain str, list[str] of DNS server IP addresses)
def resolveIPFromDNS(hostname, DNSList):
    # hostname of domain being analysed
    domain = hostname
    compiledList = []
    # set optional Cloudflare public DNS server
    # DNSList is 5 IPs each belonging to a DNS server
    # Local DNS, AARNET, OptusDNS, GoogleDNS, CloudFlare
    for DNSIP in DNSList:
        # Nslookup is a module that is a wrapper for dnspython designed to
        # further abstract the process of DNS lookups for simplicities sake
        # a custom DNS server can be provided with the argument dns_servers
        # dns_query is built with Nslookup and DNSIP as dns_servers argument
        dns_query = Nslookup(dns_servers=[DNSIP])
        # Having set the DNS server for dns_query the .dns_lookup() function
        # takes a domain str and returns an object that uses the set DNS
        # server to retrieve IP information about the domain
        ips_record = dns_query.dns_lookup(domain)
        # ips_record.answer retrieves list[str] of IPs linked to the domain
        # gathered from the allocated DNS server
        # tuple(str,list[str]) -> (DNS Server IP, [IPs linked to hostname])
        tuple = (DNSIP, ips_record.answer)
        # tuple is added to compiledList
        compiledList.append(tuple)
        tuple = ()
    # compiled list returns a list of tuples containing DNS Server IP and a
    # list of IPs linked to hostname from that DNS server
    # list[tuple(str,list[str]),tuple(str,list[str])]
    # e.g. [("1.1.1.1",['13.236.255.202', '13.55.150.53'])]
    return compiledList


def isIPPrivate(ip):
    try:
        result = ipaddress.ip_address(ip).is_private
    except Exception:
        result = "Bogon IP"
    return result


# stripDomainName takes argument of str domain (https://www.google.com/)
def stripDomainName(domainName):
    # returns the index of :// in a string or -1 if not found
    positionofWWW = domainName.find('://')
    # checks http in domainName
    if "http" in domainName:
        # shifts index 3 past :// in the domain
        # ":" returns the remainder of the string after ://
        WebsiteNOHttp = domainName[positionofWWW+3:]
    else:
        # If http in domain name, change to + 3, if no http, change to +1
        # idea being no http means no :// and positionofWWW = -1
        # -1 plus 1 is index 0 and ":" provides the remainder of string
        WebsiteNOHttp = domainName[positionofWWW+1:]
    # WebsiteNOHttpNoSlash removes forward slash at end of domains with no http
    WebsiteNOHttpNoSlash = WebsiteNOHttp.replace('/', "")
    # Conditional checks WebsiteNOHttp begins with www.
    if 'www.' == WebsiteNOHttp[0:4]:
        # WebsiteNoWWWNoSlash returns domains without www.
        # slash may still be at end of domain as WebsiteNOHttpNoSlash not used
        WebsiteNoWWWNoSlash = WebsiteNOHttp[4:]
    else:
        # www. is absent thus domain begains without it i.e google.com/
        # slash may still trail domain at this stage
        WebsiteNoWWWNoSlash = WebsiteNOHttp
    if '/' == WebsiteNoWWWNoSlash[-1]:
        # removes trailing / from domain
        WebsiteNoWWWNoSlash = WebsiteNoWWWNoSlash[0:-1]
    # returns key value pair dictionary
    return {
        'WebsiteNOHttp': WebsiteNOHttp,
        'WebsiteNOHttpNoSlash': WebsiteNOHttpNoSlash,
        'WebsiteNoHttpNoWWWNoSlash': WebsiteNoWWWNoSlash
        }
