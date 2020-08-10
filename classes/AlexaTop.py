from csv import DictReader
import tldextract


class AlexaTop:

    def __init__(self, path):
        self.__alexa_toplist = dict()
        self.__names_only = list()

        with open(path, "r") as f:

            reader = DictReader(f)

            for row in reader:
                domain = row.get("domain", None)

                if domain is None:
                    continue
                else:
                    entry = dict()
                    entry["domain"] = domain

                    parsed = tldextract.extract(domain)

                    entry["tld"] = parsed.suffix
                    entry["name"] = parsed.domain
                    entry["subdomain"] = parsed.subdomain

                    self.__names_only.append(parsed.domain)
                    self.__alexa_toplist[domain] = entry

    def score(self, domain):
        if self.__alexa_toplist.get(domain.name + "." + domain.tld, False):
            domain.set_subscore("alexa", {"score": False,
                                          "note": "Domain in alexa toplist"})
        else:
            # TODO: Make sure this is optimized
            if filter(lambda top_name: top_name in domain.domain,
                      self.__names_only):
                domain.set_subscore("alexa", {"score": True,
                                              "note": "Possible domain squatting/impersonation"})
            else:
                domain.set_subscore("alexa", {"score": False,
                                              "note": "Domain not alexa toplist and does not appear to be impersonation"})

