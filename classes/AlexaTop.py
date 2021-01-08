from csv import reader


class AlexaTop:
    # Score is a boolean value
    def __init__(self, alexa_toplist_path):
        self.alexa_toplist = set()
        with open(alexa_toplist_path, "r") as f:
            r = reader(f)

            for entry in r:
                self.alexa_toplist.add(entry[1])

    def score(self, domain):
        # Test Code
        '''
        print("domain_name:", domain.name)
        print("domain_tld:", domain.tld)
        print("domain_subdomain:", domain.subdomain)
        '''
        domain_name = domain.name
        if domain.subdomain is not None:
            domain_name = domain.name + "." + domain.subdomain
            # Test Code
            # print("domain with subdomain", domain_name)
        if domain_name + "." + domain.tld in self.alexa_toplist:
            result = True
            domain.set_subscore("alexatop", {"score": result,
                                             "note": "Scored domain in alexa top 1m."})
        else:
            result = False
            domain.set_subscore("alexatop", {"score": result,
                                             "note": "Scored domain not in alexa top 1m."})
        return result

'''
alexatop = AlexaTop("../datasets/alexa_top_100k.csv")
from classes.Domain import Domain

# Testing on a single domain. Example scores:
test_domain0 = Domain("telkom.co.za", "idk", 0)  # inAlexatop score = 0
print("\ntelkom.co.za")
print("returned score0:", alexatop.score(test_domain0))
test_domain1 = Domain("douane.gov.fr", "idk", 0) # gov.kr AlexaTop domain
print("\ndouane.gov.fr")
print("returned score1:", alexatop.score(test_domain1))
'''