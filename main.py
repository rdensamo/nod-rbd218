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
from classes.Domain import Domain
from classes.MalwareDomains import MalwareDomains
from classes.Phishtank import Phishtank


def main():
    domains = list()
    queried_entry = dict()

    malware_domains = MalwareDomains("mal_domains/justdomains.txt")
    phishtank = Phishtank("./mal_domains/verified_online.csv")

    # Create elasticsearch object,
    es = Elasticsearch([ES_SOCKET])

    # Build query using lucene query string
    query = Q("query_string",
              # TODO: _exists_:age may not be trustworthy
              query="brotype:dns-tracker AND _exists_:age")

    # Only get domains from the 2020.04.29 BRO index
    search = Search(using=es, index="bro-2020.04.29")

    # Execute the query
    res = search.query(query)

    # Get results from ES one at a time, parse into Domain objects, add objects
    # to domains.
    for hit in res.scan():
        queried_entry['dom_name'] = getattr(hit, "query", None)
        current_domain = Domain(getattr(hit, "query", None),
                                getattr(hit, 'registrar', None),
                                getattr(hit, "age", None))

        malware_domains.score(current_domain)
        phishtank.score(current_domain)
        # TODO: registrar.score(current_domain)
        domains.append(current_domain)


if __name__ == "__main__":
    main()
