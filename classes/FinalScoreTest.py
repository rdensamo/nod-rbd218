import json
import os
from csv import DictReader

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
from classes.AlexaLevenSimilarity import AlexaLevenSimilarity
import numpy as np
import matplotlib.pyplot as plt

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

        # if self._path is None:
        # print("Scoring Domains from Elasticsearch")
        # else:
        # print("Scoring Domains from Flat JSON File")

    def combineScore(self):
        subscore_weights = dict()
        return

    def simplecombineScore0(self, current_domain):
        # TODO: Make raw_final_score dict so it is easier to determine which subscore was which score get .values
        raw_final_score = dict()
        # if found in malwaredomains list or phishtank give the domain the max score
        # TODO: Later I probably want to use set_subscore instead of simplescores and say phishtank or malware
        # TODO: for why a domain got a domain score of 10
        if current_domain.simplescores['malware_domain'] or current_domain.simplescores['phishtank']:
            return 10

        # if found in alexatop give it the minimum score
        if current_domain.simplescores['alexatop']:
            return 0

        if current_domain.simplescores['isBogon']:
            raw_final_score['isBogon'] = 10
            return 10

        # TODO: Do we just want to return if it doesn't resolve ?
        # TODO: why would we want to continue scoring ?
        resolves = current_domain.simplescores['resolves']
        alexaLev = current_domain.simplescores['AlexaLevSim_score']
        raw_final_score['AlexaLevSim_score'] = int(alexaLev * 10)

        # if it is typosquatting lehigh make that part of the score 10
        # TODO: consider making the final score a 10
        if current_domain.simplescores['lehigh-typosquat']:
            raw_final_score['lehigh-typosquat'] = 10
        # If it is not then don't include it in final score just omit it

        # if it does not resolve slightly risky
        raw_final_score['resolves'] = 6

        if resolves:
            raw_final_score['resolves'] = 5
            # TODO: might want to change this threshold value .8 ?
            # TODO: or scale how you want to increase the score instead of just adding 2
            if alexaLev >= .8:
                # if it resolves and resembles a Alexa top domains this could be a phishing domain
                # increase score
                raw_final_score['resolves'] = 10
            # return sum(raw_final_score.values()) / len(raw_final_score)

        # Already had thresholded TTL risk in the class itself
        raw_final_score['ttlRisk'] = int(current_domain.simplescores['ttlRisk'] * 10)
        # If it is ever found in the spamhausreg list - set subscore to 10 because this is very rare
        if current_domain.simplescores['spamhausreg'] is not False:
            raw_final_score['spamhausreg'] = 10

        # raw_final_score['zonefiles_tld'] = int(current_domain.simplescores['zonefiles_tld'] * 10)

        # GETTING DOMAINTOOLREGISTRAR SCORES
        # print("domaintools", current_domain.simplescores['domaintoolsregistrars'])
        a = current_domain.simplescores['domaintoolsregistrars']
        b = current_domain.simplescores['knujon']
        c = current_domain.simplescores['DomainNameEntropy']
        d = current_domain.simplescores['registrar_prices']
        e = current_domain.simplescores['SpamhausTld']
        f = current_domain.simplescores['domain_age']
        scoreRange = 10
        for i in range(scoreRange - 1):
            if a < self.__domain_tools[0]:
                # raw_final_score.append(i)
                raw_final_score['domaintoolsregistrars'] = i
            if self.isbetween(a, self.__domain_tools[i], self.__domain_tools[i + 1]):
                # raw_final_score.append(i + 1)
                raw_final_score['domaintoolsregistrars'] = i + 1
            if b < self.__knujon[0]:
                # raw_final_score.append(i)
                raw_final_score['knujon'] = i
            if self.isbetween(b, self.__knujon[i], self.__knujon[i + 1]):
                # raw_final_score.append(i + 1)
                raw_final_score['knujon'] = i + 1
            if c < self.__entropy[0]:
                # raw_final_score.append(i)
                raw_final_score['DomainNameEntropy'] = i

            if self.isbetween(c, self.__entropy[i], self.__entropy[i + 1]):
                # raw_final_score.append(i + 1)
                raw_final_score['DomainNameEntropy'] = i + 1

            if d < self.__regprice[0]:
                # raw_final_score.append(i)
                raw_final_score['registrar_prices'] = i

            if self.isbetween(d, self.__regprice[i], self.__regprice[i + 1]):
                # raw_final_score.append(i + 1)
                raw_final_score['registrar_prices'] = i + 1

            if e < self.__spamtld[0]:
                # raw_final_score.append(i)
                raw_final_score['SpamhausTld'] = i
            if self.isbetween(e, self.__spamtld[i], self.__spamtld[i + 1]):
                # raw_final_score.append(i + 1)
                raw_final_score['SpamhausTld'] = i + 1

            if f < self.__domain_age[0]:
                # raw_final_score.append(i)
                raw_final_score['domain_age'] = i
            if self.isbetween(f, self.__domain_age[i], self.__domain_age[i + 1]):
                # raw_final_score.append(i + 1)
                raw_final_score['domain_age'] = i + 1

        if a > self.__domain_tools[9]:
            # raw_final_score.append(10)
            raw_final_score['domaintoolsregistrars'] = 10

        if b > self.__knujon[9]:
            # raw_final_score.append(10)
            raw_final_score['knujon'] = 10

        if c > self.__entropy[9]:
            # raw_final_score.append(10)
            raw_final_score['DomainNameEntropy'] = 10

        if d > self.__regprice[9]:
            # raw_final_score.append(10)
            raw_final_score['registrar_prices'] = 10

        if e > self.__spamtld[9]:
            # raw_final_score.append(10)
            raw_final_score['SpamhausTld'] = 10

        if f > self.__domain_age[9]:
            # raw_final_score.append(10)
            raw_final_score['domain_age'] = 10

        # TODO Thurday 12/17: Add 'isNotResolves', 'isBogon', 'ttlRisk', 'spamhausreg', 'zonefiles_tld',
        #  TODO: 'lehigh-typosquat', 'AlexaLevSim_score', 'AlexaLevSim_domain'

        avg_raw_final = sum(raw_final_score.values()) / len(raw_final_score)
        # print("\ncurrent domain: ", current_domain.domain)
        # print("total raw score: ", raw_final_score)
        # print("\navg score: ", avg_raw_final)

        return avg_raw_final

    def isbetween(self, x, x_min, x_max):
        return x_min <= x <= x_max

    def getScore0(self):
        final_score = -1
        # TODO: Change this so it uses path attribute and not hard coded

        # "../script_results/All_ES_domains_1026.json"
        with open(self._path, "r") as f:
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

        # TODO: Consider removing, doesnt produce good scores
        # zonefiles_tld = TldScoring("../datasets/ZoneFilesTLDs.html")
        alexatop = AlexaTop("../datasets/alexa_top_100k.csv")
        domain_age = DomainAge()
        lehigh_typo = LehighTypoSquat("../datasets/lehigh-typostrings.txt")
        alexaLSim = AlexaLevenSimilarity()

        i = 0

        scored = 0
        dom_count = 0
        for hit in data:
            dom_count = dom_count + 1
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
            current_domain.set_simplescore('resolves', resolver.score(current_domain)[0])
            current_domain.set_simplescore('isBogon', resolver.score(current_domain)[1])
            current_domain.set_simplescore('ttlRisk', resolver.score(current_domain)[2])
            current_domain.set_simplescore('spamhausreg', spamhaus_reg.score(current_domain))
            current_domain.set_simplescore('SpamhausTld', spamhaus_tld.score(current_domain))
            # TODO: TOO slow to score right now
            # current_domain.set_simplescore('zonefiles_tld', zonefiles_tld.score(current_domain))

            current_domain.set_simplescore('alexatop', alexatop.score(current_domain))
            current_domain.set_simplescore('domain_age', DomainAge.score(current_domain))
            current_domain.set_simplescore('lehigh-typosquat', lehigh_typo.score(current_domain))
            current_domain.set_simplescore('AlexaLevSim_score', alexaLSim.score(current_domain)[0])
            current_domain.set_simplescore('AlexaLevSim_domain', alexaLSim.score(current_domain)[1])
            current_domain.set_simplescore('DomainName', current_domain.domain)
            current_domain.set_simplescore('Registrar', current_domain.registrar)

            avg_score = self.simplecombineScore0(current_domain)
            current_domain.set_simplescore('final_score', str(avg_score))

            # TODO: if we are using the other subscore system with nested json + note
            # TODO: for now using the simplescore method because it is easier to graph and do analysis
            # TODO: for final product switch and update set_subscore as same values as simplescore
            current_domain.set_subscore("final_score",
                                        {"score": str(avg_score),
                                         "note": "This is the final score based on average subscores"})

            print(current_domain.simplescores)
            print('------------------------------------------------------------------domain #', dom_count)

            # return

            documents.append(current_domain.simplescores)

            if dom_count % 10 == 0:
                file_name = "c_" + str(dom_count) + "final_scores01_phish_data0112.json"
                # write the scores from all the datsets into one file of scores
                with open(file_name, "w") as f:
                    f.write(json.dumps(documents))
                    f.flush()
                    os.fsync(f.fileno())

        with open("../script_results/finaldomainscores0112.json", "w") as f:
            f.write(json.dumps(documents))
        f.close()
        return avg_score

    def get_score_single_domain(self, current_domain, check_phish=False, check_mal=False, check_alexa=False):

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

        # TODO: Consider removing, doesnt produce good scores
        # zonefiles_tld = TldScoring("../datasets/ZoneFilesTLDs.html")
        alexatop = AlexaTop("../datasets/alexa_top_100k.csv")
        domain_age = DomainAge()
        lehigh_typo = LehighTypoSquat("../datasets/lehigh-typostrings.txt")
        alexaLSim = AlexaLevenSimilarity()

        current_domain.set_simplescore('malware_domain', malware_domains.score(current_domain))
        # current_domain.set_simplescore('zonefile_domain', zonefile_domains.score(current_domain))

        if not check_phish:
            current_domain.set_simplescore('phishtank', phishtank.score(current_domain))
        else:
            current_domain.set_simplescore('phishtank', False)

        if not check_alexa:
            current_domain.set_simplescore('alexatop', alexatop.score(current_domain))
        else:
            current_domain.set_simplescore('alexatop', False)

        if not check_mal:
            current_domain.set_simplescore('malware_domain', malware_domains.score(current_domain))
        else:
            current_domain.set_simplescore('malware_domain', False)

        current_domain.set_simplescore('domaintoolsregistrars', domaintools_reg.score(current_domain))
        current_domain.set_simplescore('knujon', knujon.score(current_domain))
        current_domain.set_simplescore('DomainNameEntropy', entropy.score(current_domain))
        current_domain.set_simplescore('registrar_prices', registrar_prices.score(current_domain))
        current_domain.set_simplescore('resolves', resolver.score(current_domain)[0])
        current_domain.set_simplescore('isBogon', resolver.score(current_domain)[1])
        current_domain.set_simplescore('ttlRisk', resolver.score(current_domain)[2])
        current_domain.set_simplescore('spamhausreg', spamhaus_reg.score(current_domain))
        current_domain.set_simplescore('SpamhausTld', spamhaus_tld.score(current_domain))
        # TODO: TOO slow to score right now
        # current_domain.set_simplescore('zonefiles_tld', zonefiles_tld.score(current_domain))

        current_domain.set_simplescore('domain_age', DomainAge.score(current_domain))
        current_domain.set_simplescore('lehigh-typosquat', lehigh_typo.score(current_domain))
        current_domain.set_simplescore('AlexaLevSim_score', alexaLSim.score(current_domain)[0])
        current_domain.set_simplescore('AlexaLevSim_domain', alexaLSim.score(current_domain)[1])
        current_domain.set_simplescore('DomainName', current_domain.domain)
        current_domain.set_simplescore('Registrar', current_domain.registrar)

        avg_score = self.simplecombineScore0(current_domain)
        current_domain.set_simplescore('final_score', str(avg_score))

        # TODO: if we are using the other subscore system with nested json + note
        # TODO: for now using the simplescore method because it is easier to graph and do analysis
        # TODO: for final product switch and update set_subscore as same values as simplescore
        current_domain.set_subscore("final_score",
                                    {"score": str(avg_score),
                                     "note": "This is the final score based on average subscores"})

        return avg_score


# Scoring from JSON File
''' 
# "../script_results/All_ES_domains_1026.json"
# elk_path = 'C:/Users/rbd218/PycharmProjects/nod/scripts/domainscores1027_norm.json'
elk_path = '../scripts/domainscores1027_norm.json'
s = FinalScore(elk_path)
# s = FinalScore()
# print(s.type)
# print(s.combineScore())
s.getScore0()
'''

# Single domain Scoring Tests
'''
s = FinalScore()
test_domain0 = Domain("elccircuit.com", "idk", 0)
print(s.get_score_single_domain(test_domain0))
'''

# Scoring Phish and malware domain lists
# I want to score
s = FinalScore()
path_alexa20k = '../scripts/who_is_bulk_results_alexa_20k.txt'
path_maldoms = '../scripts/who_is_bulk_results_mal_all.txt'
path_phish = '../scripts/who_is_bulk_results_phish_all.txt'
path_elk = '../scripts/all_elasticsearch_domains_1026.csv'
datasets = list()

datasets.append(path_maldoms)
datasets.append(path_phish)
datasets.append(path_alexa20k)
datasets.append(path_elk)

# TODO: Get the average
# TODO: plot the scores

domain_scores = dict()
NUM_DOMAINS = 500
domain_scoring = dict()
domain_scoring["domain_from"] = list()
domain_scoring["domain_score"] = list()
domain_scoring["domain_name"] = list()
# domain_scoring["domain_subscores"] = list()
# Store subscores to plot them by color [alexa, phish and malware] to figure out
# best subscores and change weighted averages appropriately
domain_scoring["domaintoolsregistrars"] = list()
domain_scoring["knujon"] = list()
domain_scoring["DomainNameEntropy"] = list()
domain_scoring["registrar_prices"] = list()
domain_scoring["isBogon"] = list()
domain_scoring["ttlRisk"] = list()
domain_scoring["SpamhausTld"] = list()
domain_scoring["domain_age"] = list()
domain_scoring["AlexaLevSim_score"] = list()
documents = list()
# TODO : Include and change boolean values like "resolves" to 0 and 1 to graph them as well
domain_scoring["resolves"] = list()
# TODO: not really using domain_scores anymore, variable may be redundant
# domain0_scores["maleware"] = list()
# domain_scores["phishtank"] = list()
# domain_scores["alexatop"] = list()
# domain_scores["observed"] = list()
# print("list ", domain_scores)
for i in range(len(datasets)):
    path = datasets[i]

    with open(path, "r", encoding='utf-8') as f:
        print("\n\n\nfile:", str(path))
        reader = DictReader(f)
        dom_count = 0
        for row in reader:
            dom_count = dom_count + 1
            # print("dom_count:", dom_count)
            if dom_count > NUM_DOMAINS:
                break

            # registrar, domain are the columns
            # entry_reg = row["registrar"]
            # entry_dom = row["domain"]
            if row["age"] and row["registrar"] is not None:
                current_domain = Domain(row['domain'],
                                        row['registrar'], float(row["age"]))
            elif row["registrar"] is not None:
                current_domain = Domain(row['domain'],
                                        row['registrar'])
            else:
                print("line 448", current_domain, " row[domain]: ", row['domain'])
                current_domain = Domain(row["domain"])

            domain_score = s.get_score_single_domain(current_domain, True, True, True)
            print("Line 450 Domain: ", current_domain.domain, "Score: ", domain_score)
            print("---line 448", current_domain.simplescores)
            # print("datasets", str(datasets[i]).lower().find("elasticsearch") != -1, ": ", datasets[i])
            # if str(datasets[i]).lower().find("mal") != -1 : mal_dom_scores[current_domain] = domain_score
            # TODO: might want to store the domain names in dict too
            # Source: geeksforgeeks.org/python-ways-to-create-a-dictionary-of-lists/ -how to build dict of lists
            if str(datasets[i]).lower().find("mal") != -1:
                # domain_scores["maleware"].append(domain_score)
                domain_scoring["domain_from"].append("maleware")
                # domain_scoring["domain_score"].append(domain_score)
                # domain_scoring["domain_name"].append(current_domain.domain)
            elif str(datasets[i]).lower().find("phish") != -1:
                # domain_scores["phishtank"].append(domain_score)
                domain_scoring["domain_from"].append("phishtank")
                # domain_scoring["domain_score"].append(domain_score)
                # domain_scoring["domain_name"].append(current_domain.domain)
            elif str(datasets[i]).lower().find("elasticsearch") != -1:
                # domain_scores["observed"].append(domain_score)
                domain_scoring["domain_from"].append("observed")
                # domain_scoring["domain_score"].append(domain_score)
                # domain_scoring["domain_name"].append(current_domain.domain)
            elif str(datasets[i]).lower().find("alexa") != -1:
                # domain_scores["alexatop"].append(domain_score)
                domain_scoring["domain_from"].append("alexatop")
            domain_scoring["domain_score"].append(domain_score)
            domain_scoring["domain_name"].append(current_domain.domain)

            domain_scoring["domaintoolsregistrars"].append(current_domain.simplescores["domaintoolsregistrars"])
            domain_scoring["knujon"].append(current_domain.simplescores["knujon"])
            domain_scoring["DomainNameEntropy"].append(current_domain.simplescores["DomainNameEntropy"])
            domain_scoring["registrar_prices"].append(current_domain.simplescores["registrar_prices"])
            domain_scoring["ttlRisk"].append(current_domain.simplescores["ttlRisk"])
            domain_scoring["SpamhausTld"].append(current_domain.simplescores["SpamhausTld"])
            domain_scoring["domain_age"].append(current_domain.simplescores["domain_age"])
            domain_scoring["AlexaLevSim_score"].append(current_domain.simplescores["AlexaLevSim_score"])
            if current_domain.simplescores["resolves"] == True:
                domain_scoring["resolves"] = 1
            else:
                domain_scoring["resolves"] = 0

        documents.append(current_domain.simplescores)

# THIS ONE MAY BE MISSING THE PHISH, MAL, AND ALEXA LABELS I NEED for weka testing
with open("../script_results/documents_domainscores0212_FinalTest_NOLABEL.json", "w") as f:
    f.write(json.dumps(documents))

with open("../script_results/domain_scoring_domainscores0212_FinalTest_LABELm.json", "w") as f:
    f.write(json.dumps(domain_scoring))

        # print("line 499 domain_scoring: ", domain_scoring)

            # else: print("Error in file naming. Please rename files with mal, phish, alexa or es for elasticsearch domains")
# print("es",domain_scores["observed_domains"])


# TODO: should use plotly and pandas
# pd.DataFrame.from_dict(data)
# print("mal_domains", mal_dom_scores.values())


import pandas as pd

print("\ndomain scoring : ", domain_scoring)

df = pd.DataFrame(domain_scoring,
                  columns=['domain_from', 'domain_score', 'domain_name', 'domaintoolsregistrars', 'knujon',
                           'DomainNameEntropy', 'registrar_prices', 'ttlRisk', 'SpamhausTld', 'domain_age',
                           'AlexaLevSim_score', 'resolves'])

print("\n df ", df)
# Note: Need to import plotly too not just plotly.express
import plotly
import plotly.express as px

fig = px.histogram(df, x="domain_score", color="domain_from")

fig.show()

# html file
plotly.offline.plot(fig,
                    filename='C:/Users/rbd218/PycharmProjects/nod/classes/Graphs/Feb11_500_MalPhishAlexaObs_hist_fixed_observed.html')
# TODO: phishtank domains not being scored high enough - maybe can use something from weka random forests
# TODO: to figure out how to make our system correctly score high / identify bad domains
# TODO - no score distinction between Alexatop, phish and mal graph them to se
# TODO: after plotting 500 domains each, find a way to improve the scoring system


fig1 = px.histogram(df, x="domaintoolsregistrars", color="domain_from")
fig1.show()
plotly.offline.plot(fig1, filename='C:/Users/rbd218/PycharmProjects/nod/classes/Graphs/Feb11_500_domaintoolsregistrars.html')

fig2 = px.histogram(df, x="knujon", color="domain_from")
fig2.show()
plotly.offline.plot(fig2, filename='C:/Users/rbd218/PycharmProjects/nod/classes/Graphs/Feb11_500_knujon.html')

fig3 = px.histogram(df, x="DomainNameEntropy", color="domain_from")
fig3.show()
plotly.offline.plot(fig3, filename='C:/Users/rbd218/PycharmProjects/nod/classes/Graphs/Feb11_500_DomainNameEntropy.html')

fig4 = px.histogram(df, x="registrar_prices", color="domain_from")
fig4.show()
plotly.offline.plot(fig4, filename='C:/Users/rbd218/PycharmProjects/nod/classes/Graphs/Feb11_500_registrar_prices.html')

fig5 = px.histogram(df, x="ttlRisk", color="domain_from")
fig5.show()
plotly.offline.plot(fig5, filename='C:/Users/rbd218/PycharmProjects/nod/classes/Graphs/Feb11_500_ttlRisk.html')

fig6 = px.histogram(df, x="SpamhausTld", color="domain_from")
fig6.show()
plotly.offline.plot(fig6, filename='C:/Users/rbd218/PycharmProjects/nod/classes/Graphs/Feb11_500_SpamhausTld.html')

fig7 = px.histogram(df, x="domain_age", color="domain_from")
fig7.show()
plotly.offline.plot(fig7, filename='C:/Users/rbd218/PycharmProjects/nod/classes/Graphs/Feb11_500_domain_age.html')

fig8 = px.histogram(df, x="AlexaLevSim_score", color="domain_from")
fig8.show()
plotly.offline.plot(fig8, filename='C:/Users/rbd218/PycharmProjects/nod/classes/Graphs/Feb11_500_AlexaLevSim_score.html')

fig9 = px.histogram(df, x="resolves", color="domain_from")
fig9.show()
plotly.offline.plot(fig9, filename='C:/Users/rbd218/PycharmProjects/nod/classes/Graphs/Feb11_500_resolves.html')

# Sources
# https://plotly.com/python/histograms/
# https://medium.com/plotly/introducing-plotly-express-808df010143d
# https://www.geeksforgeeks.org/how-to-convert-dictionary-to-pandas-dataframe/
# https://stackoverflow.com/questions/59815797/plotly-how-to-save-plotly-express-plot-into-a-html-or-static-image-file
