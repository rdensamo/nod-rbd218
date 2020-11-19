from csv import DictReader
from urllib import parse


class Phishtank:
    def __init__(self, path):
        self.__pt_domains_dict = dict()

        with open(path, "r", encoding='utf-8') as f:

            reader = DictReader(f)

            for row in reader:

                if row["url"] in [None, ""]:
                    break

                # TODO: Double check if this needs to be optimized
                pt_entry = row

                entry_domain = parse.urlparse(row["url"]).netloc

                if entry_domain not in self.__pt_domains_dict:
                    self.__pt_domains_dict[entry_domain] = pt_entry

    # method to write phishtank urls to file of phishtank domain names
    # to conduct entropy analysis on domain name
    def write_phish_domains(self, path):
        fil = open('../mal_domains/phishdomainsonly.txt', 'a')

        with open(path, "r", encoding='utf-8') as f:

            reader = DictReader(f)

            for row in reader:

                if row["url"] in [None, ""]:
                    break

                # TODO: Double check if this needs to be optimized
                pt_entry = row

                entry_domain = parse.urlparse(row["url"]).netloc + "\n"
                fil.write(entry_domain)  # Writes to the file used .write() method
                # fil.close()  # Closes file

    def score(self, domain):
        # Try to get an entry from the malwaredomains hashmap using
        # domain as the key.
        entry = self.__pt_domains_dict.get(domain.domain, None)
        phish_url = "None"

        if entry is not None:
            phish_url = entry["url"]

        domain.set_subscore("phishtank",
                            {"score": (entry is not None),
                             "url": phish_url})
        result = entry is not None
        return result


'''
path = "../mal_domains/verified_online.csv"
phishtank = Phishtank(path)
phishtank.write_phish_domains(path)
'''
