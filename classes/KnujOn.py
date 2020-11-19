from bs4 import BeautifulSoup
import requests
from classes.Domain import Domain


class KnujOn:
    def __init__(self, path=None):
        self.__knuj_domains_dict = dict()
        self.MAX_KNUJ_SCORE = -1

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
            # print(reg_name)
            # print(reg_score)
            # TODO: use regular expressions for cleaning strings rather than functions --faster
            reg_score = reg_score.lstrip().rstrip().replace(",", "")
            try:
                self.__knuj_domains_dict[reg_name] = float(reg_score)
            except:
                continue
                # probably wasn't a number
        self.MAX_KNUJ_SCORE = max(self.__knuj_domains_dict.values())

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
            # replaced this line from False to .6
            # TODO: find a better solution to missing values
            domain.set_subscore("knujon", {"score": 0.6, "note": "Registrar score not found"})
            return 0.6

        # print("value is ", self.__knuj_domains_dict[real_reg])

        # Made sure the strings in our knujon data are what we expect to see from the registrar field in a domain
        # Tends to generally match well - changed common registrars anyway so lookups work always
        # because registrar names for the same registrar in dns-tracker are not always consistent

        domain.set_subscore("knujon",
                            {"score": self.__knuj_domains_dict[real_reg],
                             "registrar": domain.registrar})
        return self.__knuj_domains_dict[real_reg] / self.MAX_KNUJ_SCORE


# Testing Code
'''
knu = KnujOn("../datasets/KnujOn.html")
score = knu.score(Domain("qq.com", "Everyones Internet Ltd. dba SoftLayer", 0))
'''
