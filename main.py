from pprint import pprint

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
from Domain import Domain
import csv


def known_bad_domains():
    #  initialized an empty dictionary of bad domains
    # mal_domain_dict = {}
    # dict of dicts
    mal_domains_dict = dict()
    process_mal_domains(mal_domains_dict)
    process_phi_tank(mal_domains_dict)
    # print(mal_domains_dict)
    print(len(mal_domains_dict))
    return mal_domains_dict


def process_mal_domains(mal_domains_dict):
    mal_entry = dict()
    # Malware Domains:
    # read in the bad domains into the dictionary
    f = open("mal_domains/justdomains.txt", "r")
    for row in f:
        row = row.rstrip()
        mal_entry['dom_name'] = row
        mal_entry["length"] = len(row)
        mal_entry["source"] = "malwaredomains"
        # TODO: implement appending the sub-domains and other fields?
        # mal_entry['sub_dom'] = len(x)
        # https://www.geeksforgeeks.org/python-test-if-dictionary-contains-unique-keys-and-values/
        if mal_entry['dom_name'] not in mal_domains_dict:
            mal_domains_dict[row] = mal_entry  # works because domain name is unique
            # print(mal_entry)
    # why not fetch phish tank automatically ? because it will be the most updated - will make
    # it less work for us later on ? Forgot the reason
    # Having a dict of dict's makes sense because we want different keys or additional
    # keys depending on the library source of known bad
    print(len(mal_domains_dict))
    return mal_domains_dict


def process_phi_tank(mal_domains_dict):
    phi_entry = dict()
    with open('mal_domains/verified_online.csv', encoding="utf8", mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        line_count = 0
        for row in csv_reader:
            # other attributes in file we may want:
            # phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
            phi_entry['dom_name'] = row['url']
            phi_entry["length"] = len(row)
            phi_entry['source'] = "phishtank"
            # TODO: get the domain with out the http stuff
            if line_count == 0:
                line_count += 1
            if phi_entry['dom_name'] not in mal_domains_dict:
                mal_domains_dict[row['url']] = phi_entry
            # print(row)
            line_count += 1
        print(line_count)
    return mal_domains_dict


'''
Don't we want to query and do the lookup (bad domain list, who-is etc..) at the same time 
so we don't loop multiple times 
'''


def query_elastic(mal_domains_dict):
    domains = list()
    queried_entry = dict()
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
        domains.append(Domain(getattr(hit, "query", None),
                              getattr(hit, 'registrar', None),
                              getattr(hit, "age", None)))
        if queried_entry['dom_name'] in mal_domains_dict:
            # TODO: set score to max
            print("found in mal_domains_dict")
        else:
            # TODO: Function for whether domain resolves and update score
            # TODO: Function that breaks it into sub-domains and update score
            # TODO: Function for who-is lookup and update score
            # TODO: Function check trusted registrar list and update score
            # TODO: Function(s) for age, GTLD, and other checks
            print(getattr(hit, "query", None))

            # Dump domains list to stdout
    # print(domains)


def main():
    mal_domains_dict = known_bad_domains()
    query_elastic(mal_domains_dict)


if __name__ == "__main__":
    main()
