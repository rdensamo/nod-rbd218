import os
from csv import DictReader

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q
import json
import threading
import time

import sys
import os.path

# https://stackoverflow.com/questions/21005822/what-does-os-path-abspathos-path-joinos-path-dirname-file-os-path-pardir
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

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
# from classes.TldScoring import TldScoring                     # **  newly added domains
from classes.AlexaTop import AlexaTop
from classes.DomainAge import DomainAge
# TODO: Hadn't added LehighTypoSquat subscore !
from classes.LehighTypoSquat import LehighTypoSquat
from classes.AlexaLevenSimilarity import AlexaLevenSimilarity

documents = list()

path_phish = '../scripts_results/who_is_bulk_results_phish_all.txt'
path_maldoms = '../scripts_results/who_is_bulk_results_mal_all.txt'
# TODO: Need to rescore zonefiles and write class for it
path_zone = '../scripts_results/who_is_bulk_results_zone_all.txt'

path_alexa2k = '../scripts_results/who_is_bulk_results_alexa2k_all.txt'
path_alexa1m = '../scripts_results/who_is_bulk_results_alexa1m.txt'


def parseRegDomFile(file_paths):
    for i in range(len(file_paths)):
        path = file_paths[i]
        with open(path, "r", encoding='utf-8') as f:

            reader = DictReader(f)
            dom_count = 0
            for row in reader:
                dom_count = dom_count + 1
                print("dom_count:", dom_count)
                if dom_count > 20000:
                    break

                if row["registrar"] in [None, ""]:
                    break

                # registrar,domain are the columns
                entry_reg = row["registrar"]
                entry_dom = row["domain"]

                # TODO: the labeled part the phish_tank = true or alexatop = true in the final json output
                current_domain = Domain(row['domain'],
                                        row['registrar'],
                                        "False")  # TODO: Can try to extrapolate this value or use other
                # TODO: missing value techniques currently do not have AGE information from
                #  who-is

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
                #               # zonefiles_tld = TldScoring("../datasets/ZoneFilesTLDs.html")
                alexatop = AlexaTop("../datasets/alexa_top_2k.csv")
                domain_age = DomainAge()
                lehigh_typo = LehighTypoSquat("../datasets/lehigh-typostrings.txt")
                alexaLSim = AlexaLevenSimilarity()

                current_domain.set_simplescore('alexatop', alexatop.score(current_domain))
                current_domain.set_simplescore('malware_domain', malware_domains.score(current_domain))
                # current_domain.set_simplescore('zonefile_domain', zonefile_domains.score(current_domain))
                current_domain.set_simplescore('phishtank', phishtank.score(current_domain))

                current_domain.set_simplescore('domaintoolsregistrars', domaintools_reg.score(current_domain))
                current_domain.set_simplescore('knujon', knujon.score(current_domain))
                current_domain.set_simplescore('DomainNameEntropy', entropy.score(current_domain))
                current_domain.set_simplescore('registrar_prices', registrar_prices.score(current_domain))
                current_domain.set_simplescore('isNotResolves', resolver.score(current_domain)[0])
                current_domain.set_simplescore('isBogon', resolver.score(current_domain)[1])
                current_domain.set_simplescore('ttlRisk', resolver.score(current_domain)[2])
                current_domain.set_simplescore('spamhausreg', spamhaus_reg.score(current_domain))
                current_domain.set_simplescore('SpamhausTld', spamhaus_tld.score(current_domain))
                # TODO: TOO slow to score right now
                # current_domain.set_simplescore('zonefiles_tld', zonefiles_tld.score(current_domain))
                # current_domain.set_simplescore('domain_age', DomainAge.score(current_domain))
                current_domain.set_simplescore('lehigh-typosquat', lehigh_typo.score(current_domain))
                current_domain.set_simplescore('AlexaLevSim_score', alexaLSim.score(current_domain)[0])
                current_domain.set_simplescore('AlexaLevSim_domain', alexaLSim.score(current_domain)[1])
                current_domain.set_simplescore('DomainName', current_domain.domain)

                print(current_domain.simplescores)
                documents.append(current_domain.simplescores)
                if dom_count % 100 == 0:
                    file_name = "c_" + str(dom_count) + "_scored_datasets_1211_20k_alexa.json"
                    # write the scores from all the datsets into one file of scores
                    with open(file_name, "w") as f:
                        f.write(json.dumps(documents))
                        f.flush()
                        os.fsync(f.fileno())

                #    break

    # write the scores from all the datasets into one file of scores
    with open("scored_datasets_1211_20k_alexa.json", "w") as f:
        f.write(json.dumps(documents))
    f.close()


path_phish = '../scripts_results/who_is_bulk_results_phish_all.txt'
path_maldoms = '../scripts_results/who_is_bulk_results_mal_all.txt'
# TODO: Need to rescore zonefiles and write class for it
path_zone = '../scripts_results/who_is_bulk_results_zone_all.txt'

path_alexa2k = '../scripts_results/who_is_bulk_results_alexa2k_all.txt'
path_alexa1m = '../scripts_results/who_is_bulk_results_alexa1m.txt'

many_files = list()

path_alexa20k = 'who_is_bulk_results_alexa_20k.txt'
path_maldoms = 'who_is_bulk_results_mal_all.txt'
path_phish = 'who_is_bulk_results_phish_all.txt'

many_files.append(path_alexa20k)
parseRegDomFile(many_files)

'''
many_files.append(path_phish)
many_files.append(path_alexa20k)
many_files.append(path_maldoms)
parseRegDomFile(many_files)
'''

'''
many_files.append(path_phish)
threading.Thread(target=loop1_10).start()
many_files.clear()

many_files.append(path_alexa20k)
threading.Thread(target=loop1_10).start()
many_files.clear()

many_files.append(path_maldoms)
threading.Thread(target=loop1_10).start()
parseRegDomFile(many_files)
many_files.clear()
threading.Thread(target=loop1_10).start()
'''
