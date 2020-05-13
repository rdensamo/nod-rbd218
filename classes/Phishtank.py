from csv import DictReader
from urllib import parse


class Phishtank:
    def __init__(self, path):
        self.__pt_domains_dict = dict()
        # TODO: Get this remotely from a malwaredomains mirror

        with open(path, "r") as f:

            reader = DictReader(f)

            for row in reader:

                if row["url"] in [None, ""]:
                    break

                # TODO: Double check if this needs to be optimized
                pt_entry = row

                entry_domain = parse.urlparse(row["url"]).netloc

                if entry_domain not in self.__pt_domains_dict:
                    self.__pt_domains_dict[entry_domain] = pt_entry

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
