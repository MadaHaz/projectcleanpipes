from CSV_Methods import *
from website_functions import *


class ISP_Domain_Results_Interpreter:

    def __init__(self, name, ISP, ALL_ISP_LIST, domain_response_codes, default_DNS_response_codes, public_DNS_response_codes, list_of_domains):

        self.name = name
        self.ISP = ISP
        self.domains_explanation = {}
        self.All_ISPs = ALL_ISP_LIST


        otherList = list(self.All_ISPs)
        del otherList[self.All_ISPs.index(ISP)]
        self.All_Other_ISPs = otherList

        self.domain_response_codes = domain_response_codes
        self.default_DNS_response_codes = default_DNS_response_codes
        self.public_DNS_response_codes = public_DNS_response_codes
        self.list_of_domains = list_of_domains

        self.allDomainResponseCodes = self.dictOfAllDomainsOfAllISPs("CopyRight_Telstra.txt", "Response Code")
        self.allPublicDNSResponseCodes = self.dictOfAllDomainsOfAllISPs("CopyRight_Telstra.txt", "Response Code Public DNS")
        self.defaultDNSResponseCodes = self.dictOfAllDomainsOfAllISPs("CopyRight_Telstra.txt", "Response Code Default DNS")

        self.allBlockPages = self.dictOfAllDomainsOfAllISPs("CopyRight_Telstra.txt", "Block Page")
        self.allPuclicDNSBlockPages = self.dictOfAllDomainsOfAllISPs("CopyRight_Telstra.txt", "Block Page Public DNS")
        self.defaultDNSBlockPages = self.dictOfAllDomainsOfAllISPs("CopyRight_Telstra.txt", "Block Page Default DNS")

        self.allCloudFlareBlockPages = self.dictOfAllDomainsOfAllISPs("CopyRight_Telstra.txt", "Cloudflare Block Page")
        self.allPuclicDNSCloudFlareBlockPages = self.dictOfAllDomainsOfAllISPs("CopyRight_Telstra.txt", "Cloudflare Block Page Public DNS")
        self.defaultDNSCloudFlareBlockPages = self.dictOfAllDomainsOfAllISPs("CopyRight_Telstra.txt", "Cloudflare Block Page Default DNS")



        for dom in self.ISP.domains:
            print(dom)
            print(self.DNSTamperingDetection(dom))

    def get_domains(self):

        return self.ISP.domains

    def any_IP_Private(self, ipList):
        any_ISP_Resolved_IP_Is_Private = False



        for ip in ipList:

            if ip != '':
                if isIPPrivate(ip) == True:
                    any_ISP_Resolved_IP_Is_Private = True

                    return any_ISP_Resolved_IP_Is_Private


        return any_ISP_Resolved_IP_Is_Private


    def IPsInTwoLists(self, firstDNSIPList, secondDNSIPList):
        firstFoundInSecond = False
        for firstIP in firstDNSIPList:

            if firstIP in secondDNSIPList:
                firstFoundInSecond = True


                return True

        return False

    def writeResults(self):
        for dom in self.ISP.domains:
            domain = self.ISP.domains.get(dom)



            writeToCSVMethod([self.name,
            domain.domain,
            self.any_IP_Private(domain.ISP_DNS_IPS),
            self.any_IP_Private(domain.Google_DNS + domain.Cloudflare_DNS),
            domain.IntersectionOfPublicAndDefaultDNS,
            self.IPWorksDomainDoesnt(domain.responseCode, domain.ISP_IP_Response_Code),
            domain.responseCode,
            list(dict.fromkeys(domain.ISP_IP_Response_Code)),
            list(dict.fromkeys((domain.Google_DNS_Response_Code + domain.Cloudflare_DNS_Response_Code))),
            list(dict.fromkeys(self.domain_response_codes.get(dom))),
            list(dict.fromkeys(self.default_DNS_response_codes.get(dom))),
            list(dict.fromkeys(self.public_DNS_response_codes.get(dom))),
            self.printBlockPages(),
            self.blockingMethodAlgorithm(domain)],
            'Results/collated_results_interpreted.csv')


    def dictOfAllDomainsOfAllISPs(self, domainFile, reason):
        dictionaryOfDomains = {}

        with open(domainFile) as fp:
            Lines = fp.readlines()
        for name in self.list_of_domains:
            name = name.rstrip("\n")
            name = stripDomainName(name).get('WebsiteNoHttpNoWWWNoSlash').replace('.',"").rstrip("\n")
            dictionaryOfDomains[name] = {}

            for isp in self.All_ISPs:
                domain = isp.domains.get(name)

                if reason == "Response Code":
                    dictionaryOfDomains[name][isp.name] = domain.responseCode
                elif reason == "Block Page":
                    dictionaryOfDomains[name][isp.name] = domain.domainBlockPage
                elif reason == "Cloudflare Block Page":
                    dictionaryOfDomains[name][isp.name] = domain.domainCloudFlareBlockPage
                elif reason == "Response Code Public DNS":
                    dictionaryOfDomains[name][isp.name] = domain.Public_DNS_Response_Codes
                elif reason == "Block Page Public DNS":
                    dictionaryOfDomains[name][isp.name] = domain.Block_Page_Public_DNS_List
                elif reason == "Cloudflare Block Page Public DNS":
                    dictionaryOfDomains[name][isp.name] = domain.Cloudflare_Block_Page_Public_DNS_List
                elif reason == "Response Code Default DNS":
                    dictionaryOfDomains[name][isp.name] = domain.ISP_IP_Response_Code
                elif reason == "Block Page Default DNS":
                    dictionaryOfDomains[name][isp.name] = domain.Default_DNS_Block_Page
                elif reason == "Cloudflare Block Page Default DNS":
                    dictionaryOfDomains[name][isp.name] = domain.Default_DNS_Cloudflare_Block_Page
                else:
                    dictionaryOfDomains[name][isp.name] = "Didn't input a reason"


                #for time efficiency, do all of these and make it a dictionary

        return dictionaryOfDomains

    def IsWebsiteLive(self, domain_name):


        for isp in self.All_ISPs:

            #checks if accessing the domain name returns a 200 response code, and also whether it doesnt return a blockpage
            if (self.allDomainResponseCodes.get(domain_name).get(isp.name) == '200' and
            (str2bool(self.allBlockPages.get(domain_name).get(isp.name)) == False and
            str2bool(self.allCloudFlareBlockPages.get(domain_name).get(isp.name)) == False)):

                return True

            for ip in range (len(self.allPublicDNSResponseCodes.get(domain_name).get(isp.name))):
                if (self.allPublicDNSResponseCodes.get(domain_name).get(isp.name)[ip] == '200' and
                str2bool(self.allPuclicDNSBlockPages.get(domain_name).get(isp.name)[ip]) == False and
                str2bool(self.allPuclicDNSCloudFlareBlockPages.get(domain_name).get(isp.name)[ip]) == False):
                    return True

            for ip in range (len(self.defaultDNSResponseCodes.get(domain_name).get(isp.name))):


                if (self.defaultDNSResponseCodes.get(domain_name).get(isp.name)[ip] == '200' and
                str2bool(self.defaultDNSBlockPages.get(domain_name).get(isp.name)[ip]) == False and
                str2bool(self.defaultDNSCloudFlareBlockPages.get(domain_name).get(isp.name)[ip]) == False):
                    return True

        return False

    def DNSTamperingDetection(self, domain_name):
        isp = self.ISP



        if isp.domains.get(domain_name).IntersectionOfPublicAndDefaultDNS == False:

            for ip in range (len(isp.domains.get(domain_name).ISP_DNS_IPS)):

                #loop through every default dns IP, to check if every IP is a dud
                if ('200' == isp.domains.get(domain_name).ISP_IP_Response_Code[ip] and
                str2bool(self.defaultDNSBlockPages.get(domain_name).get(isp.name)[ip]) == False and
                str2bool(self.defaultDNSCloudFlareBlockPages.get(domain_name).get(isp.name)[ip]) == False):

                    #no tampering detected because an ip address from default dns works
                    return False

            for ip in range (len(isp.domains.get(domain_name).Public_DNS_Response_Codes)):
                if ('200' == isp.domains.get(domain_name).Public_DNS_Response_Codes[ip] and
                isp.domains.get(domain_name).Block_Page_Public_DNS_List[ip] == False and
                isp.domains.get(domain_name).Cloudflare_Block_Page_Public_DNS_List[ip] == False):
                    print("DNS TAMPERING - public dns returns usable website but default doesnt")
                    #tampering detected, because at least one public DNS IP goes to usable websites
                    #and the default DNS does not go to usable website
                    return True


            return False


        else:
            #there is an intersection between public DNS ip's and the default DNS, thus no dns tampering
            print("NO DNS TAMPERING - Intersection of IP's detected")
            return False





        #if intersection is false, if default dns returns non-live and public dns/other default dns returns live, then dns tampering is occuring
        #still need to compare results with other ISP's
        #does default server return different DNS results from public DNS, does the different IP's have different response codes and not blockpage
        return True

    #def DifferentResultsDetection(self, domain_name):
        #see if response code and blockpages differ  from isp to isp by domain



    def isWebsiteValid(self, response_code, block_page, cloudflare_page):
        if response_code == '200' and block_page == False and cloudflare_page == False:
            return True
        else:
            return False


    def IPBlockingDetection(self, domain_name):



        Other_ISP_IP_Response_Codes = {}
        This_ISP_IP_Response_Codes = {}



        for other_isp in self.All_Other_ISPs:
            for dom in other_isp.domains:
                domain = other_isp.domains.get(dom)

                if dom in Other_ISP_IP_Response_Codes:
                    Other_ISP_IP_Response_Codes[dom] = Other_ISP_IP_Response_Codes.get(dom).append(self.isWebsiteValid(domain.responseCode, domain.domainBlockPage, domain.domainCloudFlareBlockPage))
                else:
                    Other_ISP_IP_Response_Codes[dom] = [self.isWebsiteValid(domain.responseCode, domain.domainBlockPage, domain.domainCloudFlareBlockPage)]



                for ip in range(len(domain.ISP_DNS_IPS)):
                    ip_address = domain.ISP_DNS_IPS[ip]
                    is_ip_live = self.isWebsiteValid(domain.ISP_IP_Response_Code[ip], domain.Default_DNS_Block_Page[ip], domain.Default_DNS_Cloudflare_Block_Page[ip])
                    if ip in Other_ISP_IP_Response_Codes:
                        Other_ISP_IP_Response_Codes[ip_address] = Other_ISP_IP_Response_Codes[ip_address].append(is_ip_live)
                    else:
                        Other_ISP_IP_Response_Codes[ip_address] = [is_ip_live]





        print("THIS IS HAPPENING 3 times, probs only needs to happen once, its probs iterating through every domain")
        print(self.ISP.name)
        print(Other_ISP_IP_Response_Codes)

        return True
        '''

        '''

        '''
        ListOfResponseCodes = {}
        ListOfBlockPages = {}
        for isp in self.All_ISPs:

            for dom in isp.domains:

                domain = isp.domains.get(dom)
                ListOfResponseCodes[isp.name] = domain.responseCode

        '''
        #does ip give a different response code or vary in whether it returns a blockpage to other ISP's

        return True

    def DomainNameBlockingDetection(self):
        #does ip address reutrn 200 and is not a blockpage, does domain not return 200
        #and does domain name return different response code and non blockpage
        return True

    def blockingMethodAlgorithm(self, domain):
        #Checking for DNS Tampering by comparing Public DNS IPs with ISP DNS IPs


        if self.IsWebsiteLive(domain.domain_concat_name):
            if self.DNSTamperingDetection(domain.domain_concat_name):
                return "DNS Poison"
            elif self.IPBlockingDetection(domain.domain_concat_name):
                return "IP Blocking"

        else:
            return "Domain Not Live"






    def differenceInResponseCodes(self):
        #checks if default DNS Response code differ from public

        return 1

    def domainCodeDifferentIpCode(self):
        #

        return 1

    def IPWorksDomainDoesnt(self, domainResponse, ipResponseList):
        #if DNS resolved IP's get 200 but the domain doesn't, then the domain is beying name keyword blocked

        if domainResponse != '200' and '200' in ipResponseList:
            return True
        else:
            return False

    def printBlockPages(self):
        domainBlockList = []
        for dom in self.ISP.domains:
            domain = self.ISP.domains.get(dom)

            domainBlockList.append(domain.domainBlockPage)

        return domainBlockList
