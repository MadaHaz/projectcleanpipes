from website_functions import (
    stripDomainName,
    IPResponseCodesAndText,
    requestWebsite,
    getIPAddressOfDomain,
    getMyDNS,
    scapyTracerouteWithSR,
    resolveIPFromDNS,
    listOfDNSs
)


class Domain:
    def __init__(
        self,
        domain="",
        domainNoHTTP="",
        domainNoHTTPNoSlash="",
        domainNoHTTPNoSlashNoWWW="",
        responseCode="",
        ISP_DNS="",
        ISP_DNS_IPS="",
        ISP_IP_Response_Code=[],
        Hops_to_Domain=-1,
        Traceroute="",
        AARC_DNS_IPs="",
        Resolved_IPs=[],
        Optus_DNS_IPs="",
        Google_DNS="",
        Cloudflare_DNS="",
        Response_Code_Different_DNS_List={},
        AARC_DNS_Response_Code="",
        Optus_DNS_Response_Code="",
        Google_DNS_Response_Code="",
        Cloudflare_DNS_Response_Code="",
        Block_Page_Different_DNS_List={},
        AARC_DNS_Block_Page="",
        Optus_DNS_Block_Page="",
        Google_DNS_Block_Page="",
        Cloudflare_DNS_Block_Page="",
        domainBlockPage="",
        Cloudflare_Block_Page_Different_DNS_List={},
        domainCloudFlareBlockPage="",
        AARC_DNS_Cloudflare_Block_Page="",
        Optus_DNS_Cloudflare_Block_Page="",
        Google_DNS_Cloudflare_Block_Page="",
        Cloudflare_DNS_Cloudflare_Block_Page="",
        Default_DNS_Block_Page=[],
        Default_DNS_Cloudflare_Block_Page=[]
    ):
        # Raw Results
        # domain to domainNoHTTPNoSlashNoWWW passed as argument
        # contains stripped and unstripped iterations of domain str
        self.domain = domain
        self.domainNoHTTP = domainNoHTTP
        self.domainNoHTTPNoSlash = domainNoHTTPNoSlash
        self.domainNoHTTPNoSlashNoWWW = domainNoHTTPNoSlashNoWWW
        # domain_concat removes "." from WebsiteNoHTTPNoWWWNoSlash
        # example "google.com" -> "domain_googlecom"
        self.domain_concat_name = 'domain_{}'.format(
            stripDomainName(domain)
            .get('WebsiteNoHttpNoWWWNoSlash')
            .replace('.', "")
            )
        # conditional runs if str for responseCode or domainBlockPage
        # or domainCloudFlareBlockPage is empty which means the site has
        # not been queried
        if (
            responseCode == "" or
            domainBlockPage == "" or
            domainCloudFlareBlockPage == ""
        ):
            # queries domain and processes response for responseCode(str),
            # domainBlockPage(boolean) and domainCloudFlareBLockPage(boolean)
            # return_Response_Code returns a dictionary of the mentioned values
            self.domainResults = self.return_Response_Code()
        else:
            self.domainResults = None
        # conditional should set responseCode to response from domainResults
        if responseCode == "":
            # bug here, I think that the return_Response_Code() is returning
            # an error string, bug was caused when i was reading in results to
            # the domain it was unecessarilly calling the
            # return_Response_Code() method, pretty sure this issue is resolved
            self.responseCode = self.domainResults.get('ResponseCode')
        else:
            # if responseCode is set the value remains the same
            self.responseCode = responseCode
        # conditional should set domainBlockPage to response from domainResults
        if domainBlockPage == "":
            self.domainBlockPage = self.domainResults.get('BlockPage')
        else:
            self.domainBlockPage = domainBlockPage
        # conditional should set domainCloudFlareBlock page to response
        # from domainResults
        if domainCloudFlareBlockPage == "":
            self.domainCloudFlareBlockPage = (
                self.domainResults.get('CloudflareBlockPage')
            )
        else:
            # if domainCloudFlareBlockPage is set the value is the same
            self.domainCloudFlareBlockPage = domainCloudFlareBlockPage
        # a query on your DNS resolver is run and a nameserver str is retrieved
        # the conditional sets the retrieved nameserver as ISP_DNS
        if ISP_DNS == "":
            self.ISP_DNS = self.return_DNS()
        else:
            self.ISP_DNS = ISP_DNS
        # the conditional sets ISP_DNS_IPS to a list of IPs linked to domain
        if ISP_DNS_IPS == "":
            # return_ISP_IP_List() returns a list of IPs in str format
            ipList = self.return_ISP_IP_List()
            # isinstance checks that str(list) is in str format
            # if this doesnt run something has gone wrong or list[str] was ret
            if isinstance(ipList, str):
                # removes '
                ipList = (
                    # removes list characters: whitespace, brackets, apostrophe
                    # split turns the str into a list of IP addresses
                    ipList
                    .replace("[", "")
                    .replace("]", "")
                    .replace(" ", "")
                    .replace("'", "")
                    .split(";")
                    )
            # ISP_DNS_IPS is a list[str]
            self.ISP_DNS_IPS = ipList
        else:
            try:
                # runs if value is already set
                ipList = ISP_DNS_IPS
                self.ISP_DNS_IPS = ipList
            except Exception:
                # the same as the previous statement
                # could be redundant
                self.ISP_DNS_IPS = ISP_DNS_IPS
        # the conditional sets ISP_IP_Response_Code
        if ISP_IP_Response_Code == []:
            # sets ISP_IP_Response_Code as a list[int] of IP response codes
            self.ISP_IP_Response_Code = self.IPResponseCodesListFromString()
        else:
            # runs if ISP_IP_Response_Code is already set
            self.ISP_IP_Response_Code = ISP_IP_Response_Code
        # the conditional sets Default_DNS_Block_Page if its empty
        if Default_DNS_Block_Page == []:
            # IPResponseCodesAndText is a function from website_functions.py
            # the function takes self.ISP_DNS_IPS which is a list[str] of
            # IPs linked to a specific domain and returns a dictionary
            # .get('blockPageList') is list[boolean] type and is from testing
            # the IPS against HTML searches for blocked page strings
            self.Default_DNS_Block_Page = IPResponseCodesAndText(
                self.ISP_DNS_IPS
                ).get('blockPageList')
        # executes if Default_DNS_Block_Page is not empty
        else:
            self.Default_DNS_Block_Page = Default_DNS_Block_Page
        # the conditional sets Default_DNS_Cloudflare_Block_Page if its empty
        if Default_DNS_Cloudflare_Block_Page == []:
            # IPResponseCodesAndText is a function from website_functions.py
            # the function takes self.ISP_DNS_IPS which is a list[str] of
            # IPs linked to a specific domain and returns a dictionary
            # .get('cloudFlareBlockPageList') is list[boolean] type and is from
            # testing the IPS against HTML searches for cloud flare blocked str
            self.Default_DNS_Cloudflare_Block_Page = IPResponseCodesAndText(
                self.ISP_DNS_IPS
                ).get('cloudFlareBlockPageList')
        # executes if Default_DNS_Cloudflare_Block_Page is not empty
        else:
            self.Default_DNS_Cloudflare_Block_Page = (
                Default_DNS_Cloudflare_Block_Page
            )
        # the conditional sets Traceroute if it's empty
        if Traceroute == "":
            # calls Domain() function tracerouteToDomain()
            # sets Traceroute to list[str] of IP address route to destination
            self.Traceroute = self.tracerouteToDomain()
        else:
            # executes if Traceroute is not empty
            self.Traceroute = Traceroute
        # conditional runs if Hops_to_Domain has not been set
        if Hops_to_Domain == -1:
            # takes len() of Traceroute list[str] and set it to Hops_to_Domain
            self.Hops_to_Domain = len(self.Traceroute)
        else:
            # executes if Hops_to_Domain is -1
            self.Hops_to_Domain = Hops_to_Domain
        # conditional runs if Resolved_IPs has not been set
        if Resolved_IPs == []:
            # calls Domain() function return_IPs_Different_DNS()
            # returns list[tuple(str,list[str]),tuple(str,list[str])]
            # list is comprised of tuples. The tuples first value is a string.
            # the first value is the IP address of the DNS server queried.
            # the second value is a list of IPs the DNS server returned when
            # querying the hostname under investigation.
            # there should be a tuple for each of the five DNS servers queried.
            self.Resolved_IPs = self.return_IPs_Different_DNS()
        else:
            # executes if Resolved_IPs is not empty
            self.Resolved_IPs = Resolved_IPs
        # Resolved_IPs contains a list of tuples for the following DNS servers:
        # Resolved_IPs[0]->(Local DNS Server IP, Hostname IP results list)
        # Resolved_IPs[1]->(AARNet DNS Server IP, Hostname IP results list)
        # Resolved_IPs[2]->(OptusDNS DNS Server IP, Hostname IP results list)
        # Resolved_IPs[3]->(GoogleDNS DNS Server IP, Hostname IP results list)
        # Resolved_IPs[4]->(Cloudflare DNS Server IP, Hostname IP results list)
        # conditional sets AARC_DNS_IPs to list[str] from Resolved_IPs AARNET
        # results listing IPs from AARNet's DNS linked to the hostname
        if AARC_DNS_IPs == "":
            self.AARC_DNS_IPs = self.Resolved_IPs[1][1]
        else:
            # executes if AARC_DNS_IPs is not empty
            self.AARC_DNS_IPs = AARC_DNS_IPs
        # conditional sets Optus_DNS_IPs to list[str] from Resolved_IPs
        # OptusDNS results listing IPs connected to domain
        if Optus_DNS_IPs == "":
            self.Optus_DNS_IPs = self.Resolved_IPs[2][1]
        else:
            # executes if Optus_DNS_IPs is not empty
            self.Optus_DNS_IPs = Optus_DNS_IPs
        # conditional sets Google_DNS to list[str] from Resolved_IPs
        # GoogleDNS results listing IPs connected to domain
        if Google_DNS == "":
            self.Google_DNS = self.Resolved_IPs[3][1]
        else:
            # executes if Google_DNS is not empty
            try:
                # this block iterates through Google_DNS str or list[str]
                # and changes the formatting of the str or str in list
                # removing spaces and single quotes from strs
                # if there is an error the value is set back to Google_DNS
                ipList = []
                for ip in Google_DNS:
                    ipList.append(ip.replace(" ", "").replace("'", ""))
                self.Google_DNS = ipList
            except Exception:
                # splitting in to a list
                self.Google_DNS = Google_DNS
        # conditional sets Cloudflare_DNS to list[str] from Resolved_IPs
        # Cloudflare DNS results listing IPs connected to domain
        if Cloudflare_DNS == "":
            self.Cloudflare_DNS = self.Resolved_IPs[4][1]
        else:
            # executes if Cloudflare_DNS is not empty
            try:
                # this block iterates through Cloudflare_DNS str or list[str]
                # and changes the formatting of the str or list[str]
                # removing spaces and single quotes from strs
                # if there is an error the value is set back to Cloudflare_DNS
                ipList = []
                for ip in Cloudflare_DNS:
                    ipList.append(ip.replace(" ", "").replace("'", ""))
                self.Cloudflare_DNS = ipList
            except Exception:
                # splitting in to a list
                self.Cloudflare_DNS = Cloudflare_DNS
        # sets Public_DNS_Ips to list[str] list of IPs linked to domain
        # by appending Cloudflare_DNS list to Google_DNS list in assignment
        self.Public_DNS_Ips = self.Google_DNS + self.Cloudflare_DNS
        # conditional sets Response_Code_Different_DNS_List if its empty
        if Response_Code_Different_DNS_List == {}:
            # Response_Code_Different_DNS_List is assigned a dictionary with
            # keys: AARC, Optus, Google, Cloudflare DNS that hold list[int]
            # the held values refer to http status codes retrieved from
            # querying the IP addresses linked to the domain through the
            # specific DNS servers
            self.Response_Code_Different_DNS_List = self.IPResponseCodesList
        else:
            # executes if Response_Code_Different_DNS_List is not empty
            self.Response_Code_Different_DNS_List = (
                Response_Code_Different_DNS_List
            )
        # conditional sets AARC_DNS_Response_Code
        if AARC_DNS_Response_Code == "":
            # Response_Code_Different_DNS_List().get('AARC') retrieves
            # HTTP status code list for ARRC domain linked IPs
            self.AARC_DNS_Response_Code = (
                self.Response_Code_Different_DNS_List().get('AARC')
            )
        else:
            # executes if AARC_DNS_Response_Code is not empty
            self.AARC_DNS_Response_Code = AARC_DNS_Response_Code
        # conditional sets Optus_DNS_Response_Code
        if Optus_DNS_Response_Code == "":
            # Response_Code_Different_DNS_List().get('Optus') retrieves
            # HTTP status code list for Optus domain linked IPs
            self.Optus_DNS_Response_Code = (
                self.Response_Code_Different_DNS_List().get('Optus')
            )
        else:
            # executes if Optus_DNS_Response_Code is not empty
            self.Optus_DNS_Response_Code = Optus_DNS_Response_Code
        # conditional sets Google_DNS_Response_Code
        if Google_DNS_Response_Code == "":
            # Response_Code_Different_DNS_List().get('Google') retrieves
            # HTTP status code list for Google domain linked IPs
            self.Google_DNS_Response_Code = (
                self.Response_Code_Different_DNS_List().get('Google')
            )
        else:
            # executes if Google_DNS_Response_Code is not empty
            self.Google_DNS_Response_Code = Google_DNS_Response_Code
        # conditional sets Cloudflare_DNS_Response_Code
        if Cloudflare_DNS_Response_Code == "":
            # Response_Code_Different_DNS_List().get('Cloudflare') retrieves
            # HTTP status code list for Cloudflare domain linked IPs
            self.Cloudflare_DNS_Response_Code = (
                self.Response_Code_Different_DNS_List().get('Cloudflare')
            )
        else:
            # executes if Cloudflare_DNS_Response_Code is not empty
            self.Cloudflare_DNS_Response_Code = Cloudflare_DNS_Response_Code
        # sets Public_DNS_Response_Codes to list[int] of status codes linked to
        # public IP listings for domain by adding Google_DNS_Response_Code to
        # Cloudflare_DNS_Response_Code list
        self.Public_DNS_Response_Codes = (
            self.Google_DNS_Response_Code + self.Cloudflare_DNS_Response_Code
        )
        # ERROR - this function's output is faulty
        self.ISP_IP_in_Non_ISP_IP = self.Is_ISP_IP_In_NonISP_DNS_IP()
        # Results Analysis
        # IPsInTwoLists(list[str],list[str]) takes two lists of IPS
        # ISP_DNS_IPS are the IPs linked to the domain through local DNS server
        # Public_DNS_Ips are the IPs linked to the domain through Public
        # DNS servers
        # returns true if IP in both lists
        self.IntersectionOfPublicAndDefaultDNS = self.IPsInTwoLists(
            self.ISP_DNS_IPS, self.Public_DNS_Ips
            )
        # self.DomainBlockPage = self.
        # put in some blockpage lists and cloudflare page lists,
        # exam same as "ISP_IP_in_Non_ISP_IP"
        if Block_Page_Different_DNS_List == {}:
            self.Block_Page_Different_DNS_List = self.IPBlockPageList()
        else:
            self.Block_Page_Different_DNS_List = Block_Page_Different_DNS_List
        if AARC_DNS_Block_Page == "":
            self.AARC_DNS_Block_Page = (
                self.Block_Page_Different_DNS_List.get('AARC')
                )
        else:
            self.AARC_DNS_Block_Page = AARC_DNS_Block_Page
        if Optus_DNS_Block_Page == "":
            self.Optus_DNS_Block_Page = (
                self.Block_Page_Different_DNS_List.get('Optus')
            )
        else:
            self.Optus_DNS_Block_Page = Optus_DNS_Block_Page
        if Google_DNS_Block_Page == "":
            self.Google_DNS_Block_Page = (
                self.Block_Page_Different_DNS_List.get('Google')
            )
        else:
            self.Google_DNS_Block_Page = Google_DNS_Block_Page
        if Cloudflare_DNS_Block_Page == "":
            self.Cloudflare_DNS_Block_Page = (
                self.Block_Page_Different_DNS_List.get('Cloudflare')
            )
        else:
            self.Cloudflare_DNS_Block_Page = Cloudflare_DNS_Block_Page
        self.Block_Page_Public_DNS_List = (
            self.Google_DNS_Block_Page + self.Cloudflare_DNS_Block_Page
        )
        if Cloudflare_Block_Page_Different_DNS_List == {}:
            self.Cloudflare_Block_Page_Different_DNS_List = (
                self.IPCloudFlareBlockPageList()
            )
        else:
            self.Cloudflare_Block_Page_Different_DNS_List = (
                Cloudflare_Block_Page_Different_DNS_List
            )
        if AARC_DNS_Cloudflare_Block_Page == "":
            self.AARC_DNS_Cloudflare_Block_Page = (
                self.Cloudflare_Block_Page_Different_DNS_List.get('AARC')
            )
        else:
            self.AARC_DNS_Cloudflare_Block_Page = (
                AARC_DNS_Cloudflare_Block_Page
            )
        if Optus_DNS_Cloudflare_Block_Page == "":
            self.Optus_DNS_Cloudflare_Block_Page = (
                self.Cloudflare_Block_Page_Different_DNS_List.get('Optus')
            )
        else:
            self.Optus_DNS_Cloudflare_Block_Page = (
                Optus_DNS_Cloudflare_Block_Page
            )
        if Google_DNS_Cloudflare_Block_Page == "":
            self.Google_DNS_Cloudflare_Block_Page = (
                self.Cloudflare_Block_Page_Different_DNS_List.get('Google')
            )
        else:
            self.Google_DNS_Cloudflare_Block_Page = (
                Google_DNS_Cloudflare_Block_Page
            )
        if Cloudflare_DNS_Cloudflare_Block_Page == "":
            self.Cloudflare_DNS_Cloudflare_Block_Page = (
                self.Cloudflare_Block_Page_Different_DNS_List.get('Cloudflare')
            )
        else:
            self.Cloudflare_DNS_Cloudflare_Block_Page = (
                Cloudflare_DNS_Cloudflare_Block_Page
            )
        self.Cloudflare_Block_Page_Public_DNS_List = (
            self.Google_DNS_Cloudflare_Block_Page
            + self.Cloudflare_DNS_Cloudflare_Block_Page
        )

    # ERROR - Boolean is meaningless
    def Is_ISP_IP_In_NonISP_DNS_IP(self):
        # formula should be: if dns ip's provide 404's, if non isp
        # dns's provide 200's some form of tampering is happening
        # calls Domain() function getPublicDNSResponses but no assignment
        self.getPublicDNSResponses()
        # DNSIPList is a combined list of Google_DNS and Cloudflare_DNS IPs
        # Preyy sure this variable is already assigned
        publicDNSIPList = self.Google_DNS + self.Cloudflare_DNS
        # !!!!!flaw here
        # ISP_DNS_IPS is a list
        # ISP_DNS_IPS is a single IP address
        # .split("; ") doesnt do anything
        # this boolean doesn't do anything
        for ip in self.ISP_DNS_IPS[0].split("; "):
            if ip in publicDNSIPList:
                return True
        else:
            return False

    # ERROR - Pointless Function
    def getPublicDNSResponses(self):
        # compiledList = list[int] of status codes
        compiledList = (
            self.Google_DNS_Response_Code+self.Cloudflare_DNS_Response_Code
        )
        # dictionary return obj gets made resultsDict{}
        resultsDict = {}
        for code in compiledList:
            # the point of this dictionary is to count the number of codes
            if code in resultsDict:
                resultsDict[code] = resultsDict.get(code)+1
            else:
                resultsDict[code] = 1
        # dictionary returns a count of each code
        return resultsDict

    # return_Reponse_Code() takes domain str and http/https boolean to query
    # website for response data that returns a dictionary of responseCode str
    # BlockPage boolean and CloudflareBlockPage boolean
    def return_Response_Code(self):
        https = False
        http = False
        # conditionals check if domain is http or https a
        if self.domain[0:5] == "https":
            https = True
        if self.domain[0:5] == "http:":
            http = True
        # try catch block will throw an exception if error occurs
        try:
            # passes domainNoHTTP str, https & https booleans to requestWebsite
            # domain passed format -> www.google.com/ slash intact
            # results is a dictionary containing ResponseCode(str),
            # BlockPage(boolean) and CloudflareBlockPage
            results = requestWebsite(self.domainNoHTTP, http, https)
            print("DO WE GET TO RESULTS?")
            # returns a dictionary with results data
            return {
                'ResponseCode': results.get('RespondeCode'),
                'BlockPage': results.get('BlockPage'),
                'CloudflareBlockPage': results.get('CloudflareBlockPage')}
        except Exception as e:
            # error in the querying process
            print("NAH WE GET TO EXCEPTION")
            # error is converted to a string
            errorMessage = str(e).replace(',', ';')
            # returns query error as ResponseCode in dictionary
            return {
                'ResponseCode': errorMessage,
                'BlockPage': "N/A",
                'CloudflareBlockPage': "N/A"
                }

    # retrieves information for ISP_DNS_IPS variable
    # providing the hostname returns IP list associatiated with the domain
    def return_ISP_IP_List(self):
        # getIPAddressOfDomain takes str of domain without a slash and http
        # the function returns a tuple of IP list associated with the domain
        # index 0 is the list in str format and 1 is the list in list[str]
        return getIPAddressOfDomain(self.domainNoHTTPNoSlash)[0]

    # getMyDNS() is a function from website_functions.py
    # it returns one nameserver str  but the getMyDNS() function may have
    # retrieved multiple nameservers
    def return_DNS(self):
        return getMyDNS()

    # scapyTracerouteWithSR() is a function from website_functions.py
    # takes domain str without slash, HTTP and WWW (google.com)
    # returns list[str] of IP addresses tracing route to destination
    def tracerouteToDomain(self):
        return scapyTracerouteWithSR(self.domainNoHTTPNoSlashNoWWW)

    # IPResponseCodesAndText() is a function from website_functions.py
    def IPResponseCodesListFromString(self):
        # ISP_DNS_IPS is a list[str] of IPS associated with the domain
        IPResponsesList = self.ISP_DNS_IPS
        # IPResponseCodesAndText() is a function from website_functions.py
        # it returns {responseCodeList, blockPageList, cloudFlareBlockPageList}
        # they're of type {list[int],list[boolean],list[boolean]}
        # .get('responseCodeList') returns list[int] of status codes for IPs
        responseCodeList = (
            IPResponseCodesAndText(IPResponsesList).get('responseCodeList')
        )
        # responseCodeList is list[int] of status codes for the domain IPs
        return responseCodeList

    # resolveIPFromDNS(str, list[str]) is a function from website_functions.py
    # takes domain str without slash, HTTP and WWW (google.com)
    # listOfDNSs() is a function from website_functions.py and it returns
    # list[str] of IPs for the local DNS server and common public DNS servers
    def return_IPs_Different_DNS(self):
        # resolveIPFromDNS() returns a list[ of tuples(str, list[str])]
        # tuple(str is the DNS server IP, list[str] are the IPs linked to
        # hostname as listed by the DNS server)
        # 4 public DNS servers and the client's local DNS server are tested
        # with a hostname query to retrieve the IP in the tuple.
        DifferentDNSIPs = (
            resolveIPFromDNS(self.domainNoHTTPNoSlashNoWWW, listOfDNSs())
            )
        return DifferentDNSIPs

    # IPResponseCodesList is a function from website_functions.py
    def IPResponseCodesList(self):
        # returns a dictionary for AARC, Optus, Google, Cloudflare DNS
        # values passed to IPResponseCodesAndText are a list[str] of IPs
        # linked to the DNS server being queried for the domain
        # .get('responseCodeList') returns list[int] of http status code
        # responses matching queries performed on the provided list of IPs
        # to IPResponseCodesAndText()
        return {
            'AARC': IPResponseCodesAndText(
                self.AARC_DNS_IPs
                ).get('responseCodeList'),
            'Optus': IPResponseCodesAndText(
                self.Optus_DNS_IPs
                ).get('responseCodeList'),
            'Google': IPResponseCodesAndText(
                self.Google_DNS
                ).get('responseCodeList'),
            'Cloudflare': IPResponseCodesAndText(
                self.Cloudflare_DNS
                ).get('responseCodeList')
        }

    def IPBlockPageList(self):
        return {
            'AARC': IPResponseCodesAndText(
                self.AARC_DNS_IPs
                ).get('blockPageList'),
            'Optus': IPResponseCodesAndText(
                self.Optus_DNS_IPs
                ).get('blockPageList'),
            'Google': IPResponseCodesAndText(
                self.Google_DNS
                ).get('blockPageList'),
            'Cloudflare': IPResponseCodesAndText(
                self.Cloudflare_DNS
                ).get('blockPageList')}

    def IPCloudFlareBlockPageList(self):
        return {
            'AARC': IPResponseCodesAndText(
                self.AARC_DNS_IPs
                ).get('cloudFlareBlockPageList'),
            'Optus': IPResponseCodesAndText(
                self.Optus_DNS_IPs
                ).get('cloudFlareBlockPageList'),
            'Google': IPResponseCodesAndText(
                self.Google_DNS
                ).get('cloudFlareBlockPageList'),
            'Cloudflare': IPResponseCodesAndText(
                self.Cloudflare_DNS
                ).get('cloudFlareBlockPageList')
        }

    # IPsInTwoList(list[str],list[str])
    # returns true if any of the IPs in list 1 is in list 2
    def IPsInTwoLists(self, firstDNSIPList, secondDNSIPList):
        # firstFoundInSecond = False
        for firstIP in firstDNSIPList:
            if firstIP in secondDNSIPList:
                # firstFoundInSecond = True
                return True
        return False


if __name__ == "__main__":
    a = Domain()
