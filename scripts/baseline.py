from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q
import json
import time

from pprint import pprint

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
    # if found in malwaredomains list or phishtank or does not resolve give the domain the max score
    if current_domain.subscores['malware_domain']['score'] or current_domain.subscores['phishtank']['score'] \
            or not current_domain.subscores['resolves']:
        current_domain.score = 10

    # 'malwaredomains', 'phishtank', 'domaintoolsregistrars', 'knujOn', 'domain name entropy', 'prices', 'resolves',
    # 'ttl', 'SpamhausTld'
    dom_attribute = current_domain.subscores.keys()
    print(dom_attribute)
    print(current_domain.simplescores)
    print(current_domain.subscores['domaintoolsregistrars']['score'])
    break
    current_domain.set_simplescore('DomainName', current_domain.domain)
    # print(current_domain.simplescores)
    documents.append(current_domain.simplescores)


with open("../script_results/test_domainscores1109_norm.json", "w") as f:
    f.write(json.dumps(documents))
# f.close()