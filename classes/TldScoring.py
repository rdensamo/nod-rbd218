from bs4 import BeautifulSoup
import requests


# view-source:https://brandtld.news/tld/
# https://brandtld.news/tld/
# view-source:https://zonefiles.io/
# https://zonefiles.io/


class TldScoring:
    def __init__(self, path):
        self.__Tld_Scoring = dict()
        self.brand_tlds = []

        # If we would rather read it from a flat file:oooo
        # r = open(path, 'r').read()
        # soup = BeautifulSoup(r, 'html.parser')

        # Getting html of brand TLDs from brand tld website:
        brand = requests.get('https://brandtld.news/tld/')
        soup = BeautifulSoup(brand.text, 'html.parser')

        brand_results = soup.find_all('a')
        # print(brand_results)
        for tld in brand_results:
            entry = tld.text
            brand_name = entry.split('Brand TLD -')[0]
            if "@" in brand_name:
                return
            self.brand_tlds.append(brand_name)
            # print(brand_name)

    def zone_tlds(self):
        # Getting html of TLDs from zone files website:
        zone = requests.get('https://zonefiles.io/')
        soup = BeautifulSoup(zone.text, 'html.parser')

        zone_results = soup.find_all('a')
        tld_found = False
        dom_count = None
        tld_name = None
        for tld in zone_results:
            entry = tld.text
            if "zone" in entry:
                tld_found = True
                tld_name = entry.split('zone')[0]
            elif tld_found:
                dom_count = tld.string
                tld_found = False
            elif dom_count is not None and tld_name is not None:
                self.__Tld_Scoring[tld_name] = dom_count
                # print("tld name:", tld_name, "dom count:", dom_count)
                dom_count = None
                tld_name = None
        return

    def score(self, domain):
        entry = self.__Tld_Scoring.get(domain.tld, None)
        domain.set_subscore("ZoneFileBrandTld",
                                {"score": entry,
                                 "tld": domain.tld})
        if entry is not None:
            return entry
        else:
            return False

        # TODO: Need to make sure tld getter gets tld in same format


#tlds = TldScoring("../datasets/ZoneFilesTLDs.html")
