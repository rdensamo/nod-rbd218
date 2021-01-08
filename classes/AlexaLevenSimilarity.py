from csv import reader
import tldextract
from fastDamerauLevenshtein import damerauLevenshtein

path_alexa1m = '../datasets/alexa_top_1m.csv'
path_alexa100k = '../datasets/alexa_top_100k.csv'


class AlexaLevenSimilarity:
    def __init__(self, path=None):
        self.__alexa100k_domains_dict = set()

        # self.alexa_toplist = set()
        with open(path_alexa100k, "r") as f:
            r = reader(f)

            for entry in r:
                # print("entry", entry)
                self.__alexa100k_domains_dict.add(entry[1])


    def score(self, domain):
        inAlexa = False
        MAX_SIMILARITY_SCORE = -1
        MAX_SIMILARITY_DOMAIN = None
        domain_name_tld = domain.name + "." + domain.tld
        # Just checking if subdomain is None produces false results because
        # tldextract still returns something for domains with no subdomains
        # check isalpha instead
        if domain.subdomain.isalpha():
            domain_name_tld = domain.subdomain + "." + domain.name + "." + domain.tld
            # print("There is a subdomain:", domain.subdomain) # Test Code
        # print("checking Phish Domain name:", domain_name)
        if domain_name_tld in self.__alexa100k_domains_dict:
            inAlexa = True
            domain.set_subscore("AlexaLevSim", {"score": inAlexa,
                                                "note": "Scored domain in alexa top 1m."})
            # return inAlexa
            return (0, inAlexa)  # NOT RISKY IT IS AN ALEXA DOMAIN
        else:
            # if it is not an alexa domain then want to give it a score of how
            # similar it is to an alexa domain
            for a_dom in self.__alexa100k_domains_dict:

                # TODO: Do we just want to compare the domain names without the TLDs?
                # do not think so because a phishing domain could have the same tld as an alexatop
                # domain but just have characters in the domain name that are slightly different and want to catch that
                # and score those domains higher than they would be scored if we aren't including the tld
                # however short domains with the same tlds get scored too high -- need to compensate for short domains
                # score it lower
                # TODO: Do a length check so short domains that have same tlds do not get high scores
                # TODO: need to do something for short domains - decrease risk score
                sim_score = damerauLevenshtein(a_dom, domain_name_tld, similarity=True)
                if MAX_SIMILARITY_SCORE < sim_score:
                    MAX_SIMILARITY_SCORE = sim_score
                    MAX_SIMILARITY_DOMAIN = a_dom
                '''
                Improved: 
                Check just the domain name w/o tld 
                Then check tld if they match → if they don’t very risky 
                '''
                # Do not want to check "domain.name in MAX_SIMILARITY_DOMAIN" because then I would be checking
                # for substring and I want to check if the domain name is exactly the same
                # - otherwise it produces really high scores we would not want
                # have to separate the tld from the domain name from most similar alexa domain name
                # in order to check for domain name the tld

                parsed = tldextract.extract(MAX_SIMILARITY_DOMAIN)
                tld_max_sim = parsed.suffix
                domain_max_sim = parsed.domain
                # subdomain = parsed.subdomain
                if domain.name == domain_max_sim and domain.tld not in tld_max_sim:
                    domain.set_subscore("AlexaLevSim", {"score": 10,
                                                        "note": "Very similar to AlexaTop but TLD is different"})
                    # Test Code:
                    # print("note: Very similar to AlexaTop but TLD is different")
                    # print("most sim:", domain_max_sim)
                    # print("domain:", domain.name)
                    # print("subdomain:", domain.subdomain)
                    # MAX value in this class is 1 and gets scaled to 10 in different class
                    return 1, MAX_SIMILARITY_DOMAIN  # Very RISKY because domain name is similar but tld does not match

            # print("Most similar good domain:", MAX_SIMILARITY_DOMAIN)
            # print("Most similar score:", MAX_SIMILARITY_SCORE)
            return MAX_SIMILARITY_SCORE, MAX_SIMILARITY_DOMAIN




'''
als = AlexaLevenSimilarity()
from classes.Domain import Domain

# Testing on a single domain. Example scores:
test_domain0 = Domain("000webhostapp.com", "idk", 0) #inAlexatop score = 0
test_domain1 = Domain("000webhostapp.me", "idk", 0)  # DomainName inAlexatop but tld wrong score=1
test_domain2 = Domain("www.microtechscientific.com", "idk", 0) # a newly observed domain in elk score=.47
test_domain3 = Domain("file.com", "idk", 0)  # substring of a lot of Alexatop domains test score=0.5
test_domain4 = Domain("douane.gov.fr", "idk", 0) # gov.kr AlexaTop domain
print("\nreturned score0:", als.score(test_domain0))
print("\nreturned score1:", als.score(test_domain1))
print("\nreturned score2:", als.score(test_domain2))
print("\nreturned score3:", als.score(test_domain3))
print("\ndouane.gov.fr")
print("returned score4:", als.score(test_domain4))
'''

'''
path_phish = '../mal_domains/phishdomainsonly.txt'
with open(path_phish, "r", encoding='utf-8') as f:
    for domain_name in f:
        print("\n")
        test_domain = Domain(domain_name, "idk", 0)
        returned = als.score(test_domain)
        print("returned:", returned)
        print("returned similarity score :", returned[0])
        print("returned most similar good domain:", returned[1])
'''
# Test on Phish Domain List
