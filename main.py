from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q

# TODO: This library crashes on non-standard date strings
# import whois
""" 
Probably try/catch and use the other whois. Might need to
do some importlib work to get them both in.

`python-whois` `whois` from pypy
"""
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
from classes.LehighTypoSquat import LehighTypoSquat



def main():
    domains = list()
    queried_entry = dict()

    malware_domains = MalwareDomains("mal_domains/justdomains.txt")
    phishtank = Phishtank("./mal_domains/verified_online.csv")
    domaintools_reg = DomainToolsRegistrars("./datasets/domaintools_registrars.csv")
    knujon = KnujOn()
    entropy = RedCanaryEntropy()
    registrar_prices = Registrarprices("./TLD_PRICING/TLD_PRICES_AVGBYREG.csv")
    resolver = Resolver()
    spamhaus_reg = SpamhausReg()
    spamhaus_tld = SpamhausTld("./datasets/spamhaus_tlds.csv")
    zonefiles_tlc = TldScoring("./datasets/ZoneFilesTLDs.html")
    lehigh_typo_squat = LehighTypoSquat("./datasets/lehigh-typostrings.txt")

    # Create elasticsearch object,
    es = Elasticsearch([ES_SOCKET])

    # Build query using lucene query string
    query = Q("query_string",
              query="brotype:dns-tracker AND _exists_:age")

    # Only get domains from the 2020.04.29 BRO index
    search = Search(using=es, index="bro-*")

    # Execute the query
    res = search.query(query)

    # Get results from ES one at a time, parse into Domain objects, add objects
    # to domains.

    i = 0
    for hit in res.scan():
        queried_entry['dom_name'] = getattr(hit, "query", None)
        current_domain = Domain(getattr(hit, "query", None),
                                getattr(hit, 'registrar', None),
                                getattr(hit, "age", None))

        domains.append(current_domain)

        malware_domains.score(current_domain)
        phishtank.score(current_domain)
        domaintools_reg.score(current_domain)
        knujon.score(current_domain)
        entropy.score(current_domain)
        registrar_prices.score(current_domain)
        resolver.score(current_domain)
        spamhaus_reg.score(current_domain)
        spamhaus_tld.score(current_domain)
        zonefiles_tlc.score(current_domain)
        lehigh_typo_squat.score(current_domain)

        print(current_domain)
        i+= 1
        if i > 10:
            break

    print(len(domains))
    from pprint import pprint
    for domain in domains:
        pprint(domain.subscores)


if __name__ == "__main__":
    main()
