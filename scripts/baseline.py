from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q
import json
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
from classes.LehighTypoSquat import LehighTypoSquat

domains = list()
queried_entry = dict()

# to load the file from disk
data = None
documents = list()

with open("hits_9_28.json", "r") as f:
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
zonefiles_tld = TldScoring("../datasets/ZoneFilesTLDs.html")

alexatop = AlexaTop("../datasets/alexa_top_2k.csv")
domain_age = DomainAge()

i = 0
dom_tool_mean = 0
knujon_mean = 0
entropy_mean = 0
prices_mean = 0
ttl_mean = 0
spam_tld_mean = 0

for hit in data:
    # json data is custom python object
    # https://pynative.com/python-convert-json-data-into-custom-python-object/

    # gatattr - returns the value of the named attribute of an object

    current_domain = Domain(hit['_domain'],
                            hit['_registrar'],
                            hit['_age'])

    # malware_domains.score(current_domain)
    # phishtank.score(current_domain)
    # domaintools_reg.score(current_domain)
    # knujon.score(current_domain)
    # entropy.score(current_domain)
    # registrar_prices.score(current_domain)
    # resolver.score(current_domain)
    # spamhaus_reg.score(current_domain)
    # spamhaus_tld.score(current_domain)
    # zonefiles_tld.score(current_domain)
    current_domain.set_simplescore('malware_domain', malware_domains.score(current_domain))
    current_domain.set_simplescore('phishtank', phishtank.score(current_domain))
    current_domain.set_simplescore('domaintools', domaintools_reg.score(current_domain))
    current_domain.set_simplescore('knujon', knujon.score(current_domain))
    current_domain.set_simplescore('entropy', entropy.score(current_domain))
    current_domain.set_simplescore('registrar_prices', registrar_prices.score(current_domain))
    current_domain.set_simplescore('resolver', resolver.score(current_domain))
    # TODO: need to include bogon scoring
    current_domain.set_simplescore('spamhaus_reg', spamhaus_reg.score(current_domain))
    current_domain.set_simplescore('spamhaus_tld', spamhaus_tld.score(current_domain))
    current_domain.set_simplescore('zonefiles_tld', zonefiles_tld.score(current_domain))

    current_domain.set_simplescore('alexatop', alexatop.score(current_domain))
    current_domain.set_simplescore('domain_age', DomainAge.score(current_domain))
    # TODO: need to include Alexatop scoring Forest pushed 9/8/2020


    # print(current_domain.subscores)
    # if found in malwaredomains list or phishtank or does not resolve give the domain the max score
    if current_domain.subscores['malwaredomains']['score'] or current_domain.subscores['phishtank']['score'] \
            or not current_domain.subscores['resolves']:
        current_domain.score = 10

    # 'malwaredomains', 'phishtank', 'domaintoolsregistrars', 'knujOn', 'domain name entropy', 'prices', 'resolves', 'ttl', 'SpamhausTld'
    dom_attribute = current_domain.subscores.keys()
    # print(current_domain.subscores)
    # trying to filter out the domains that cause RecursionError('maximum recursion depth exceeded')
    # when calling resolves
    if "Error" not in current_domain.subscores:
        print(current_domain.subscores)
        current_domain.set_subscore('DomainName', current_domain.domain)
        current_domain.set_simplescore('DomainName', current_domain.domain)
        print(current_domain.simplescores)

        documents.append(current_domain.simplescores)


# TODO: after validating output write these to a file
with open("928_domainscores.json", "w") as f:
    f.write(json.dumps(documents))

