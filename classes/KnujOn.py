from bs4 import BeautifulSoup
import requests
from classes.Domain import Domain

class KnujOn:
    def __init__(self, path=None):
        self.__knuj_domains_dict = dict()

        # Prefer to read it from a flat file because flat file has been hand-modified for more
        # accurate registrar lookups for the first few registrars:
        r = open(path, 'r').read()
        soup = BeautifulSoup(r, 'html.parser')

        # Not preferred but works: Getting html from website:
        # r = requests.get('http://www.knujon.com/registrars/')
        # soup = BeautifulSoup(r.text, 'html.parser')

        soup = soup.ol
        results = soup.find_all('li')

        for reg in results:
            entry = reg.text
            reg_name = entry.split(':')[0]
            reg_score = entry.split(':')[1]
            self.__knuj_domains_dict[reg_name] = reg_score
            # print(reg_name)
            # print(reg_score)

    def score(self, domain):
        real_reg = None

        for registrar in self.__knuj_domains_dict.keys():
            if domain.registrar is not None:
                # for each registrar in our collection checks if it is a substring of the registrar we
                # are scoring currently
                if registrar.lower() in domain.registrar.lower():
                    real_reg = registrar
                    break

        if real_reg is None:
            domain.set_subscore("knujOn", {"score": None, "note": "Registrar score not found"})
            return

        # print("value is ", self.__knuj_domains_dict[real_reg])

        # Made sure the strings in our knujon data are what we expect to see from the registrar field in a domain
        # Tends to generally match well - changed common registrars anyway so lookups work always
        # because registrar names for the same registrar in dns-tracker are not always consistent

        domain.set_subscore("knujOn",
                            {"score": self.__knuj_domains_dict[real_reg],
                             "registrar": domain.registrar})

# Testing Code
'''
knu = KnujOn("../datasets/KnujOn.html")
score = knu.score(Domain("qq.com", "Everyones Internet Ltd. dba SoftLayer", 0))
'''

