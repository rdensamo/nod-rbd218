from bs4 import BeautifulSoup
import requests
import re


# view-source:https://brandtld.news/tld/
# https://brandtld.news/tld/
# view-source:https://zonefiles.io/
# https://zonefiles.io/

# TODO: should save a hard-copy of this ?


class TldScoring:
    # This rarely returns something that is not False
    def __init__(self, path):
        self.__Tld_Scoring = dict()
        self.MAX_Tld_SCORE = -1
        self.brand_tlds = []

        # If we would rather read it from a flat file:
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
            # print("original", brand_name)
            if "@" in brand_name:
                return
            if "." in brand_name:
                # Regular expressions better than replace
                brand_name = re.sub('[^a-zA-Z]+', '', brand_name)
                # brand_name = brand_name.replace(".", "").replace("\n", "")
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
            # Note: This if statement logic is because the tld and domain count are on different lines
            # keep if and elif statements as is
            if "zone" in entry:
                tld_found = True
                tld_name = entry.split('zone')[0]
                # TODO: use regular expressions for cleaning strings rather than functions --faster
                tld_name = tld_name.lstrip().rstrip().replace(".", "")
            elif tld_found:
                dom_count = tld.string
                tld_found = False
            elif dom_count is not None and tld_name is not None:
                # TODO: use regular expressions for cleaning strings rather than functions --faster
                dom_count = dom_count.lstrip().rstrip().replace(",", "")
                # re.sub('[0-9_]+', '', dom_count.replace(",", ""))
                try:
                    self.__Tld_Scoring[tld_name] = int(dom_count)
                    # print("---tld name:", tld_name, "dom count:", dom_count)
                    print("dom count:", int(dom_count))
                    dom_count = None
                except:
                    dom_count = None
                tld_name = None
        self.MAX_Tld_SCORE = max(self.__Tld_Scoring.values())
        # print(self.MAX_Tld_SCORE)
        return

    '''
     This returns a value from 0 to 1 if the domain tld is found in zonefiles
     returns True if it is a brandtld 
     returns False if it is none of the above 
    '''

    def score(self, domain):
        # The method that gets the domain counts for tlds and saves them in dict()
        self.zone_tlds()
        # print("------------", domain.tld)
        # print(self.__Tld_Scoring.keys())
        # print(self.brand_tlds)
        entry = self.__Tld_Scoring.get(domain.tld, None)

        if entry is None:
            # replaced this line from False to .6
            # TODO: find a better solution to missing values
            domain.set_subscore("ZoneFileBrandTld",
                                {"score": 0.6,
                                 "tld": domain.tld})
            return 0.6

        domain.set_subscore("ZoneFileBrandTld",
                            {"score": entry,
                             "tld": domain.tld})
        if entry is not None:
            return entry / self.MAX_Tld_SCORE
        else:
            isBrandTld = domain.tld in self.brand_tlds
            return isBrandTld

        # TODO: Need to make sure tld getter gets tld in same format


'''
tlds = TldScoring("../datasets/ZoneFilesTLDs.html")
tlds.zone_tlds()
'''
