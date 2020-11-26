from csv import DictReader

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q
import json

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
                # zonefiles_tld = TldScoring("../datasets/ZoneFilesTLDs.html")

                alexatop = AlexaTop("../datasets/alexa_top_2k.csv")
                # TODO: Do not have domain age information
                # domain_age = DomainAge()
                lehigh_typo = LehighTypoSquat("../datasets/lehigh-typostrings.txt")

                # LABEL FOR THE DATA "LABELED DATA"
                current_domain.set_simplescore('malware_domain', malware_domains.score(current_domain))
                # current_domain.set_simplescore('zonefile_domain', zonefile_domains.score(current_domain))
                current_domain.set_simplescore('phishtank', phishtank.score(current_domain))
                current_domain.set_simplescore('alexatop', alexatop.score(current_domain))
                # TODO : Do we check if any are in the zonefile list of bad domains ?
                current_domain.set_simplescore('domaintools', domaintools_reg.score(current_domain))
                current_domain.set_simplescore('knujon', knujon.score(current_domain))
                current_domain.set_simplescore('entropy', entropy.score(current_domain))
                current_domain.set_simplescore('registrar_prices', registrar_prices.score(current_domain))
                current_domain.set_simplescore('resolver', resolver.score(current_domain))
                current_domain.set_simplescore('spamhaus_reg', spamhaus_reg.score(current_domain))
                current_domain.set_simplescore('spamhaus_tld', spamhaus_tld.score(current_domain))
                # TODO: TOO slow to score right now
                # current_domain.set_simplescore('zonefiles_tld', zonefiles_tld.score(current_domain))
                current_domain.set_simplescore('alexatop', alexatop.score(current_domain))
                # TODO: do not have age information right now for these domains
                # current_domain.set_simplescore('domain_age', DomainAge.score(current_domain))
                current_domain.set_simplescore('lehigh_typo', lehigh_typo.score(current_domain))

                dom_attribute = current_domain.subscores.keys()
                current_domain.set_simplescore('DomainName', current_domain.domain)
                print(current_domain.simplescores)
                documents.append(current_domain.simplescores)

    # write the scores from all the datsets into one file of scores
    with open("scored_datasets_1118_ALLDATA.json", "w") as f:
        f.write(json.dumps(documents))
    f.close()


path_phish = '../scripts_results/who_is_bulk_results_phish_all.txt'
path_maldoms = '../scripts_results/who_is_bulk_results_mal_all.txt'
# TODO: Need to rescore zonefiles and write class for it
path_zone = '../scripts_results/who_is_bulk_results_zone_all.txt'

path_alexa2k = '../scripts_results/who_is_bulk_results_alexa2k_all.txt'
path_alexa1m = '../scripts_results/who_is_bulk_results_alexa1m.txt'

many_files = list()

# path1 = 'who_is_bulk_results_phish_small_test_file.txt'
# path2 = 'who_is_bulk_results_alexa_small_test_file.txt'
# path3 = 'who_is_bulk_results_mal.txt'
# path4 = 'who_is_bulk_results_zone.txt'

# path_phish = 'who_is_bulk_results_phish_all.txt'
# path_maldoms = 'who_is_bulk_results_mal_all.txt'
# path_alexa2k = 'who_is_bulk_results_alexa_all.txt'
# path_alexa1m = 'who_is_bulk_results_alexa_all_1m.txt'

path_alexa20k = 'who_is_bulk_results_alexa_all_20k.txt'
path_maldoms = 'who_is_bulk_results_mal_all.txt'
path_phish = 'who_is_bulk_results_phish_all.txt'

many_files.append(path_phish)
many_files.append(path_alexa20k)
many_files.append(path_maldoms)
parseRegDomFile(many_files)
