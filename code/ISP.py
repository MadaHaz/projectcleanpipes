from website_functions import *
from domain import Domain

class ISP:

    DNS_Tampered_Domains = {}

    def __init__(self, name, domains):
        self.name = name
        self.domains = domains





    def get_domain(self, domain_code):
        return self.domains[domain_code]

    def return_class_variables(ISP):
        return(ISP.__dict__)

    def Find_DNS_Tampered_Domains(self):

        for domain in self.domains:

        # Converting string to list
             #res = self.domains.get(domain).ISP_IP_Response_Code.strip('][').split(', ')
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


    
