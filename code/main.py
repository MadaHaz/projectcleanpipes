from website_functions import stripDomainName
import scapy.all as scapy
import csv
from domain import Domain
from ISP_Domain_Results_Interpreter import ISP_Domain_Results_Interpreter
from ISP import ISP
from CSV_Methods import writeToCSVMethod


def writeObjectToCSV(obj, writeFile):
    resultsList = [
        obj.domain,
        obj.responseCode,
        obj.ISP_DNS,
        obj.ISP_DNS_IPS,
        obj.ISP_IP_Response_Code,
        obj.Traceroute,
        obj.Hops_to_Domain,
        obj.AARC_DNS_IPs,
        obj.Optus_DNS_IPs,
        obj.Google_DNS,
        obj.Cloudflare_DNS,
        obj.AARC_DNS_Response_Code,
        obj.Optus_DNS_Response_Code,
        obj.Google_DNS_Response_Code,
        obj.Cloudflare_DNS_Response_Code,
        obj.domainBlockPage,
        obj.AARC_DNS_Block_Page,
        obj.Optus_DNS_Block_Page,
        obj.Google_DNS_Block_Page,
        obj.Cloudflare_DNS_Block_Page,
        obj.domainCloudFlareBlockPage,
        obj.AARC_DNS_Cloudflare_Block_Page,
        obj.Optus_DNS_Cloudflare_Block_Page,
        obj.Google_DNS_Cloudflare_Block_Page,
        obj.Cloudflare_DNS_Cloudflare_Block_Page,
        obj.Default_DNS_Block_Page,
        obj.Default_DNS_Cloudflare_Block_Page
        ]
    writeToCSVMethod(resultsList, writeFile)


def CalculateListOfDomains(openFile, writeFile):
    websiteList = []
    with open(openFile) as fp:
        Lines = fp.readlines()
    for line in Lines:
        websiteList.append(line.strip('\n'))
    for item in websiteList:
        domain = item
        domainStripped = stripDomainName(domain)
        WebsiteNOHttp = domainStripped.get('WebsiteNOHttp')
        WebsiteNOHttpNoSlash = domainStripped.get('WebsiteNOHttpNoSlash')
        WebsiteNoHttpNoWWWNoSlash = domainStripped.get(
            'WebsiteNoHttpNoWWWNoSlash'
            )
        print(item)
        obj = Domain(
            domain=domain,
            domainNoHTTP=WebsiteNOHttp,
            domainNoHTTPNoSlash=WebsiteNOHttpNoSlash,
            domainNoHTTPNoSlashNoWWW=WebsiteNoHttpNoWWWNoSlash
            )
        writeObjectToCSV(obj, writeFile)


def readCSVToDomain(file_names):
    results_files = file_names
    ISP_list = []
    for file in results_files:
        with open(scapy.os.path.join('../results', file)) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            line_count = 0
            domainDict = {}
            for row in csv_reader:
                if line_count == 0:
                    line_count += 1
                else:
                    name = 'domain_{}'.format(
                        stripDomainName(row[0])
                        .get('WebsiteNoHttpNoWWWNoSlash')
                        .replace('.', "")
                        )
                    print("ISP: "+str(file)+" DOMAIN: "+str(name))
                    domainDict[name] = Domain(
                        domain=row[0],
                        responseCode=row[1], ISP_DNS=row[2],
                        ISP_DNS_IPS=row[3].strip('][')
                        .replace('\'', '').replace(' ', '').split(','),
                        ISP_IP_Response_Code=row[4].strip('][').split(', '),
                        Traceroute=row[5].strip('][').split(', '),
                        Hops_to_Domain=row[6],
                        AARC_DNS_IPs=row[7].strip('][').split(', '),
                        Optus_DNS_IPs=row[8].strip('][').split(', '),
                        Google_DNS=row[9].strip('][').split(', '),
                        Cloudflare_DNS=row[10].strip('][').split(', '),
                        AARC_DNS_Response_Code=row[11].strip('][').split(', '),
                        Optus_DNS_Response_Code=row[12]
                        .strip('][').split(', '),
                        Google_DNS_Response_Code=row[13]
                        .strip('][').split(', '),
                        Cloudflare_DNS_Response_Code=row[14]
                        .strip('][').split(', '),
                        Resolved_IPs="Read from CSV",
                        Response_Code_Different_DNS_List="Read from CSV",
                        Block_Page_Different_DNS_List="Read from CSV",
                        domainBlockPage=row[15],
                        AARC_DNS_Block_Page=row[16]
                        .strip('][').replace('\'', '').split(', '),
                        Optus_DNS_Block_Page=row[17]
                        .strip('][').replace('\'', '').split(', '),
                        Google_DNS_Block_Page=row[18].strip('][')
                        .replace('\'', '').replace('\'', '').split(', '),
                        Cloudflare_DNS_Block_Page=row[19].strip('][')
                        .replace('\'', '').split(', '),
                        Cloudflare_Block_Page_Different_DNS_List="""
                            Read from CSV
                            """,
                        domainCloudFlareBlockPage=row[20],
                        AARC_DNS_Cloudflare_Block_Page=row[21].strip('][')
                        .replace('\'', '').split(', '),
                        Optus_DNS_Cloudflare_Block_Page=row[22]
                        .strip('][').replace('\'', '').split(', '),
                        Google_DNS_Cloudflare_Block_Page=row[23]
                        .strip('][').replace('\'', '').split(', '),
                        Cloudflare_DNS_Cloudflare_Block_Page=row[24]
                        .strip('][').replace('\'', '').split(', '),
                        Default_DNS_Block_Page=row[25]
                        .strip('][').replace('\'', '')
                        .replace(' ', '').split(','),
                        Default_DNS_Cloudflare_Block_Page=row[26]
                        .strip('][').replace('\'', '')
                        .replace(' ', '').split(',')
                    )
                    line_count += 1
            new_ISP = ISP("ISP_{}".format(file), domainDict)
            ISP_list.append(new_ISP)
            domainDict = {}
            new_ISP = None
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
            insertStrInToDict(
                domain_response_codes, dom, isp.domains.get(dom).responseCode
                )
            insertListInToDict(
                default_DNS_response_codes, dom, isp.domains
                .get(dom).ISP_IP_Response_Code
                )
            insertListInToDict(
                public_DNS_response_codes, dom, isp.domains
                .get(dom).Google_DNS_Response_Code
                + isp.domains.get(dom).Cloudflare_DNS_Response_Code
                )
    return {
        'domain_response_codes': domain_response_codes,
        'default_DNS_response_codes': default_DNS_response_codes,
        'public_DNS_response_codes': public_DNS_response_codes
        }


def List_Of_Domains(domainFile):
    domain_list = []
    with open('../data/' + domainFile) as fp:
        Lines = fp.readlines()
    for line in Lines:
        line = line.rstrip("\n")
        name = 'domain_{}'.format(
            stripDomainName(line)
            .get('WebsiteNoHttpNoWWWNoSlash')
            .replace('.', "")
            .rstrip("\n")
            )
        domain_list.append(name)
    return domain_list


def writeCollatedResults(ISP_List, allResponseCodes):
    domain_response_codes = allResponseCodes.get('domain_response_codes')
    default_DNS_response_codes = allResponseCodes.get(
        'default_DNS_response_codes'
        )
    public_DNS_response_codes = allResponseCodes.get(
        'public_DNS_response_codes'
        )
    for isp in ISP_List:
        # new_Results = ISP_Domain_Results_Interpreter("hey", isp)
        # new_Results.get_domains()
        # ALL_Other_ISPs = ISP_List
        # ALL_Other_ISPs.remove(isp)
        # Change the last part of this function to whichever file
        # was used to create the data.
        New_ISP_Domain_Results_Interpreter = ISP_Domain_Results_Interpreter(
            isp.name,
            isp,
            ISP_List,
            domain_response_codes,
            default_DNS_response_codes,
            public_DNS_response_codes,
            List_Of_Domains("CopyRight_Telstra.txt")
            )
        New_ISP_Domain_Results_Interpreter.writeResults()
        # ALL_Other_ISPs.append(isp)


def interpretResults(interpret_files):
    ISP_LIST = readCSVToDomain(interpret_files)
    allResponseCodes = getAllResponseCodes(ISP_LIST)
    writeCollatedResults(ISP_LIST, allResponseCodes)


def main():
    # Uncomment this for data collection. Dev Testing.
    CalculateListOfDomains(
        "../data/CopyRight_Telstra.txt",
        "../results/Optus_25Mar.csv"
        )

    # Uncomment this to interpret results. Dev Testing.
    interpret_files = ['Optus_25Mar.csv', 'AARC_12Apr.csv']
    interpretResults(interpret_files)

    # Collect data on 30 Banned Sites (BS).
    # Output file format is BS_ISPNAME_DAYMONTH_YEAR.csv, example is,
    # BS_AussieBroadband_25Apr_2024.csv
    """
    CalculateListOfDomains(
        "../data/30BannedSites_2020.txt",
        "../results/BS_AussieBroadband_25Apr_2024.csv"
        )
    """

    # Collect data on 15 Top Sites (TS).
    # Output file format is TS_ISPNAME_DAYMONTH_YEAR.csv,
    # example is, TS_AussieBroadband_25Apr_2024.csv
    """
    CalculateListOfDomains(
        "../data/15MostVisitedSites_April_2024.txt",
        "../results/TS_AussieBroadband_25Apr_2024.csv"
        )
    """

    # Interpret the results.
    # Place the output files from the previous step here. Both BS and TS
    # IMPORTANT, Make sure to change the filename in line 267 to whichever
    # file was used to make the results file you want to interpret.
    # Make sure there is only 1 file interpretted at a time.
    # LEAVE THIS FOR LATER.
    # interpret_files = ['BS_AussieBroadband_25Apr_2024.csv']
    # interpretResults(interpret_files);

    # Results are stored in ./results/collated_results_interpreted.csv
    # Change the name of that file before uploading them.
    # Format is, TYPE_ISPNAME_Collated_Results_Interpreted.csv, example is,
    # TS_AussieBroadband_Collated_Results_Interpreted.csv


if __name__ == "__main__":
    main()
