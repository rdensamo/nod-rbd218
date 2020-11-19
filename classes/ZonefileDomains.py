class ZonefileDomains:
    def __init__(self, path):
        self.__zone_domains_dict = dict()

        with open(path, "r") as f:
            for row in f:
                row = row.rstrip()
                zone_entry = dict()
                zone_entry['dom_name'] = row
                # not sure why I had the below code
                # zone_entry["length"] = len(row)
                if zone_entry['dom_name'] not in self.__zone_domains_dict:
                    self.__zone_domains_dict[row] = zone_entry

    def score(self, domain):
        # Try to get an entry from the malwaredomains hashmap using
        # domain as the key.
        entry = self.__zone_domains_dict.get(domain.domain, None)
        domain.set_subscore("zonefile",
                            {"score": (entry is not None)})
        return entry is not None
