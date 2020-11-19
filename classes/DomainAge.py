from bisect import bisect_left
from csv import DictReader
import matplotlib.pyplot as plt
import numpy as np

from classes.Domain import Domain


class DomainAge:
    # Max score possible already in table
    MAX_AGE_SCORE = 3.85
    # Approximated from the charts on page 4 and 5 of
    # https://www.domaintools.com/content/The_DmainTools_Report_Distribution_Malicious_Domain.pdf
    intervals_mo = range(0, 81, 3)
    intervals_mo_lookup = (1.45, 1.80, 3.60, 3.85, 2.10, 1.65, 1.10, 0.90, 0.40, 0.42,
                           0.49, 0.39, 0.30, 0.28, 0.31, 0.39, 0.29, 0.14, 0.20, 0.19,
                           0.18, 0.17, 0.15, 0.15, 0.14, 0.20, 0.19, 0.09)

    @staticmethod
    def score(domain):
        '''
        if domain.age < 2.074e+6:
            # First 24 days of life are most suspicious
            domain.set_subscore("age", {"score": 4.0})
        '''

        # Otherwise defer to the domain tools research
        months = domain.age / 2.628e+6
        offset = bisect_left(DomainAge.intervals_mo, months)
        score = DomainAge.intervals_mo_lookup[offset]
        domain.set_subscore("domain_age", {"score": score})
        # returns a normalized score for age
        return score / DomainAge.MAX_AGE_SCORE

    # TESTING FUNCTION FOR CODE BELOW:
    def testScore(self, bad_doms, good_doms, dom_size=1000):
        # bad domains
        key = 0
        malicious_domains = dict()
        malicious_ages = dict()
        with open(bad_doms, "r") as f:
            for row in f:
                domain = Domain(row, "registrarexample.com", 0)
                # TODO: Should registrars and age be optional in the Domain class causes error otherwise
                malicious_domains[row] = self.score(domain)

                key += 1
                if key == dom_size:
                    break

        # print(key)
        # to make sure we are graphing equal number of bad to good domains on the histogram
        if dom_size > key: dom_size = key

        key = 0
        # good domains
        alexastopdomains = dict()
        with open(good_doms, "r") as f:

            reader = DictReader(f)
            for row in reader:
                alexa_domain = row.get("domain")
                if alexa_domain is None:
                    continue
                else:
                    domain = Domain(alexa_domain, "registrarexample.com", 0)
                    alexastopdomains[domain] = self.score(domain)
                key += 1
                if key == dom_size:
                    break

        x = np.array(np.array(list(malicious_domains.values())).astype(float))
        y = np.array(np.array(list(alexastopdomains.values())).astype(float))
        plt.xlabel('Domain age', fontsize=10)
        plt.ylabel('Frequency', fontsize=10)
        plt.title('Domain age vs Frequency', fontsize=10)
        plt.hist(x, color="red")
        plt.hist(y, color="green")
        # plt.xlim(0, 1)
        path = r'../graphs/Entropy Graphs/Entropy for phish Domains and Alexa Top 1 million Domains w 10000 domains full.png'
        plt.savefig(path)
        # plt.xlim(-300)
        plt.show()
        return 0


''' 
import whois

# SOURCE: https://pypi.org/project/python-whois/
try:

    # domain = whois.query('google.com')
    # print(domain.__dict__)

    domain = whois.whois('webscraping.com')
    print(domain)
except:
    print('query failed')
'''
