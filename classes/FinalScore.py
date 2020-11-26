import json
from config import ES_SOCKET
from classes.AlexaTop import AlexaTop
from classes.Domain import Domain
from classes.DomainToolsRegistrars import DomainToolsRegistrars
from classes.KnujOn import KnujOn
from classes.MalwareDomains import MalwareDomains
# from classes.ZonefileDomains import ZonefileDomains
from classes.Phishtank import Phishtank
from classes.RedCanaryEntropy import RedCanaryEntropy
from classes.Registrarprices import Registrarprices
from classes.Resolver import Resolver
from classes.SpamhausReg import SpamhausReg
from classes.SpamhausTld import SpamhausTld
from classes.TldScoring import TldScoring
from classes.AlexaTop import AlexaTop
from classes.DomainAge import DomainAge
# TODO: Hadn't added LehighTypoSquat subscore !
from classes.LehighTypoSquat import LehighTypoSquat

domains = list()
queried_entry = dict()

# to load the file from disk
data = None
documents = list()


# Create as a singleton class
class FinalScore:
    __instance = None

    @staticmethod
    def getInstance():
        """ Static access method. """
        if FinalScore.__instance == None:
            FinalScore()
        return FinalScore.__instance

    def __init__(self, path=None):
        """ Virtually private constructor. """
        if FinalScore.__instance is not None:
            raise Exception("This class is a singleton!")
        else:
            FinalScore.__instance = self
            self._path = path
            # Thresholds
            self.__domain_tools = [0.0974, 0.1354, 0.1499, 0.1611, 0.3098, 0.3871, 0.4128, 1.0347, 1.3267, 1.4000]
            self.__knujon = [0.0500, 0.08, 0.016, 0.017, 0.26, 0.38, 0.70, 0.80, 0.945, 1]
            self.__entropy = [0.025, 0.057, 0.069, 0.127, 0.1611, 0.2, 0.4, 0.6, 0.8, 1]
            self.__regprice = [0.18, 0.20, 0.2146, 0.3051, 0.401, 0.589, 0.6, 0.761, 0.878, 1]
            self.__spamtld = [0.00249, 0.0174, 0.0287, 0.0423, 0.0623, 0.0659, 0.2, 0.289, 0.415, 0.69]
            self.__domain_age = [0.028, 0.0525, 0.0825, 0.1125, 0.2375, 0.2875, 0.4325, 0.4725, 0.5475, 0.9375]

        if self._path is None:
            print("Scoring Domains from Elasticsearch")
        else:
            print("Scoring Domains from Flat JSON File")

    def combineScore(self):
        subscore_weights = dict()
        return

    def simplecombineScore0(self, current_domain):
        raw_final_score = list()
        # if found in malwaredomains list or phishtank or does not resolve give the domain the max score
        if current_domain.subscores['malware_domain']['score'] or current_domain.subscores['phishtank']['score']:
            current_domain.score = 10
            return
        # what to do with domains that do not resolve ?

        # GETTING DOMAINTOOLREGISTRAR SCORES
        # print("domaintools", current_domain.simplescores['domaintoolsregistrars'])
        x = current_domain.simplescores['domaintoolsregistrars']
        for i in range(9):
            if x < self.__domain_tools[0]:
                raw_final_score.append(i)
                break
            if self.isbetween(x, self.__domain_tools[i], self.__domain_tools[i + 1]):
                raw_final_score.append(i + 1)
                break

        if x > self.__domain_tools[9]:
            raw_final_score.append(10)

        # GETTING KNUJON SCORES
        x = current_domain.simplescores['knujon']
        for i in range(9):
            if x < self.__knujon[0]:
                raw_final_score.append(i)
                break
            if self.isbetween(x, self.__knujon[i], self.__knujon[i + 1]):
                raw_final_score.append(i + 1)
                break

        if x > self.__knujon[9]:
            raw_final_score.append(10)

        # GETTING DOMAIN NAME ENTROPY SCORES
        x = current_domain.simplescores['DomainNameEntropy']
        for i in range(9):
            if x < self.__entropy[0]:
                raw_final_score.append(i)
                break
            if self.isbetween(x, self.__entropy[i], self.__entropy[i + 1]):
                raw_final_score.append(i + 1)
                break

        if x > self.__entropy[9]:
            raw_final_score.append(10)

        # GETTING REGISTRAR PRICE SCORES
        x = current_domain.simplescores['registrar_prices']
        for i in range(9):
            if x < self.__regprice[0]:
                raw_final_score.append(i)
                break
            if self.isbetween(x, self.__regprice[i], self.__regprice[i + 1]):
                raw_final_score.append(i + 1)
                break

        if x > self.__regprice[9]:
            raw_final_score.append(10)

        # GETTING SPAMHAUS TLD SCORES
        x = current_domain.simplescores['SpamhausTld']
        for i in range(9):
            if x < self.__spamtld[0]:
                raw_final_score.append(i)
                break
            if self.isbetween(x, self.__spamtld[i], self.__spamtld[i + 1]):
                raw_final_score.append(i + 1)
                break

        if x > self.__spamtld[9]:
            raw_final_score.append(10)

        # GETTING DOMAIN AGE SCORES
        x = current_domain.simplescores['domain_age']
        for i in range(9):
            if x < self.__domain_age[0]:
                raw_final_score.append(i)
                break
            if self.isbetween(x, self.__domain_age[i], self.__domain_age[i + 1]):
                raw_final_score.append(i + 1)
                break

        if x > self.__domain_age[9]:
            raw_final_score.append(10)

        print("\ncurrent domain: ", current_domain.domain)
        print("\ntotal raw score: ", raw_final_score)
        print("\navg score: ", sum(raw_final_score) / len(raw_final_score))

        return sum(raw_final_score) / len(raw_final_score)

    def isbetween(self, x, x_min, x_max):
        return x_min <= x <= x_max

    def getScore0(self):
        final_score = -1

        with open("../script_results/All_ES_domains_1026.json", "r") as f:
            # parses json string and get dictionary
            data = json.loads(f.read())

        malware_domains = MalwareDomains("../mal_domains/justdomains.txt")
        # zonefile_domains = ZonefileDomains('../datasets/zonefile_domains_full.txt')
        phishtank = Phishtank("../mal_domains/verified_online.csv")
        domaintools_reg = DomainToolsRegistrars("../datasets/domaintools_registrars.csv")
        knujon = KnujOn("../datasets/KnujOn.html")
        entropy = RedCanaryEntropy()
        registrar_prices = Registrarprices("../TLD_PRICING/TLD_PRICES_AVGBYREG.csv")
        resolver = Resolver()
        spamhaus_reg = SpamhausReg()
        spamhaus_tld = SpamhausTld("../datasets/spamhaus_tlds.csv")

        # TODO: Score separately on small number of data - slow
        zonefiles_tld = TldScoring("../datasets/ZoneFilesTLDs.html")
        alexatop = AlexaTop("../datasets/alexa_top_2k.csv")
        domain_age = DomainAge()
        lehigh_typo = LehighTypoSquat("../datasets/lehigh-typostrings.txt")

        i = 0

        scored = 0
        for hit in data:
            # json data is custom python object
            # https://pynative.com/python-convert-json-data-into-custom-python-object/

            # gatattr - returns the value of the named attribute of an object
            score_times = dict()
            current_domain = Domain(hit['_domain'],
                                    hit['_registrar'],
                                    hit['_age'])

            current_domain.set_simplescore('malware_domain', malware_domains.score(current_domain))
            # current_domain.set_simplescore('zonefile_domain', zonefile_domains.score(current_domain))
            current_domain.set_simplescore('phishtank', phishtank.score(current_domain))
            current_domain.set_simplescore('domaintoolsregistrars', domaintools_reg.score(current_domain))
            current_domain.set_simplescore('knujon', knujon.score(current_domain))
            current_domain.set_simplescore('DomainNameEntropy', entropy.score(current_domain))
            current_domain.set_simplescore('registrar_prices', registrar_prices.score(current_domain))
            current_domain.set_simplescore('resolves', resolver.score(current_domain))
            current_domain.set_simplescore('spamhausreg', spamhaus_reg.score(current_domain))
            current_domain.set_simplescore('SpamhausTld', spamhaus_tld.score(current_domain))
            # TODO: TOO slow to score right now
            # current_domain.set_simplescore('zonefiles_tld', zonefiles_tld.score(current_domain))
            current_domain.set_simplescore('alexatop', alexatop.score(current_domain))
            current_domain.set_simplescore('domain_age', DomainAge.score(current_domain))
            current_domain.set_simplescore('lehigh-typosquat', lehigh_typo.score(current_domain))
            current_domain.set_simplescore('DomainName', current_domain.domain)

            print(current_domain.simplescores)
            self.simplecombineScore0(current_domain)
            # return

            documents.append(current_domain.simplescores)

        with open("../script_results/finaldomainscores1118.json", "w") as f:
            f.write(json.dumps(documents))
        f.close()


path = 'C:/Users/rbd218/PycharmProjects/nod/scripts/domainscores1027_norm.json'
s = FinalScore(path)
# s = FinalScore()
# print(s.type)
#print(s.combineScore())
s.getScore0()

# TODO: should make the raw_final_score list a dict() to see better which feature is producing which value