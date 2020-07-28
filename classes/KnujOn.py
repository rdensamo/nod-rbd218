from bs4 import BeautifulSoup
import requests


class KnujOn:
    def __init__(self, path):
        self.__knuj_domains_dict = dict()

        # If we would rather read it from a flat file:
        # r = open(path, 'r').read()
        # soup = BeautifulSoup(r, 'html.parser')

        # Getting html from website:
        r = requests.get('http://www.knujon.com/registrars/')
        soup = BeautifulSoup(r.text, 'html.parser')

        soup = soup.ol
        results = soup.find_all('li')

        for reg in results:
            entry = reg.text
            # TODO: Need to store the registrar key in a way that we can do a lookup of the registrars (all lowercase?)
            # TODO: Manually look through like registrar prices - compare against elastic search
            # TODO: substring ? much harder to do samething as registrarnprices because there is more entries
            # TODO: similarity score : based on how many consecutive characters are the same & thresholding - expensive
            reg_name = entry.split(':')[0]
            reg_score = entry.split(':')[1]
            self.__knuj_domains_dict[reg_name] = reg_score
            # print(reg_name)
            # print(reg_score)

    def score(self, domain):
        entry = self.__knuj_domains_dict.get(domain.registrar, None)
        domain.set_subscore("knujOn",
                            {"score": entry,
                             "registrar": domain.registrar})



# knu = KnujOn("../datasets/KnujOn.html")
# reg = Registrarprices("../TLD_PRICING/TLD_PRICES_AVGBYREG.csv")
