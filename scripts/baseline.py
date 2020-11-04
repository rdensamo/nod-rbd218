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
dom_tool_mean = 0
knujon_mean = 0
entropy_mean = 0
prices_mean = 0
ttl_mean = 0
spam_tld_mean = 0

scored = 0
for hit in data:
    # json data is custom python object
    # https://pynative.com/python-convert-json-data-into-custom-python-object/

    # gatattr - returns the value of the named attribute of an object
    score_times = dict()
    current_domain = Domain(hit['_domain'],
                            hit['_registrar'],
                            hit['_age'])
    #t0 = time.time() * 1000
    current_domain.set_simplescore('malware_domain', malware_domains.score(current_domain))
    #t1 = time.time() * 1000
    #score_times['mal_time'] = t1 - t0
    current_domain.set_simplescore('phishtank', phishtank.score(current_domain))
    #t2 = time.time() * 1000
    #score_times['phis_time'] = t2 - t1
    current_domain.set_simplescore('domaintools', domaintools_reg.score(current_domain))
    #t3 = time.time() * 1000
    #score_times['domtools_time'] = t3 - t2
    current_domain.set_simplescore('knujon', knujon.score(current_domain))
    #t4 = time.time() * 1000
    #score_times['knujon_time'] = t4 - t3
    current_domain.set_simplescore('entropy', entropy.score(current_domain))
    #t5 = time.time() * 1000
    #score_times['entropy_time'] = t5 - t4
    current_domain.set_simplescore('registrar_prices', registrar_prices.score(current_domain))
    #t6 = time.time() * 1000
    #score_times['regprice_time'] = t6 - t5
    current_domain.set_simplescore('resolver', resolver.score(current_domain))
    #t7 = time.time() * 1000
    #score_times['resolver_time'] = t7 - t6
    current_domain.set_simplescore('spamhaus_reg', spamhaus_reg.score(current_domain))
    #t8 = time.time() * 1000
    #score_times['spamreg_time'] = t8 - t7
    current_domain.set_simplescore('spamhaus_tld', spamhaus_tld.score(current_domain))
    #t9 = time.time() * 1000
    #score_times['spamtld_time'] = t9 - t8
    # TODO: TOO slow to score right now
    # current_domain.set_simplescore('zonefiles_tld', zonefiles_tld.score(current_domain))
    #t10 = time.time() * 1000
    #score_times['zonetld_time'] = t10 - t9
    current_domain.set_simplescore('alexatop', alexatop.score(current_domain))
    #t11 = time.time() * 1000
    #score_times['alextop_time'] = t11 - t10
    current_domain.set_simplescore('domain_age', DomainAge.score(current_domain))
    #t12 = time.time() * 1000
    #score_times['domage_time'] = t12 - t11
    current_domain.set_simplescore('lehigh_typo', lehigh_typo.score(current_domain))
    '''
     for feature in score_times:
        print(feature + " took ", score_times[feature])
    break
    '''

    # print(current_domain.subscores)
    # if found in malwaredomains list or phishtank or does not resolve give the domain the max score
    if current_domain.subscores['malwaredomains']['score'] or current_domain.subscores['phishtank']['score'] \
            or not current_domain.subscores['resolves']:
        current_domain.score = 10

    # 'malwaredomains', 'phishtank', 'domaintoolsregistrars', 'knujOn', 'domain name entropy', 'prices', 'resolves',
    # 'ttl', 'SpamhausTld'
    dom_attribute = current_domain.subscores.keys()
    current_domain.set_simplescore('DomainName', current_domain.domain)
    print(current_domain.simplescores)
    documents.append(current_domain.simplescores)

    ''' 
    scored += 1
    if scored % 500 == 0:
        print("scored=", scored)
        with open("", "w") as f:
            f.write(json.dumps(documents))
        # f.close()
        # documents.clear()
    '''

with open("../script_results/domainscores1027_norm.json", "w") as f:
    f.write(json.dumps(documents))
# f.close()



'''
# TODO: after validating output write these to a file
with open("domainscores1022.json", "w") as f:
    f.write(json.dumps(documents))
'''