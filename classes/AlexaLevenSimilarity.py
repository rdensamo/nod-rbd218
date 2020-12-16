from csv import reader

from fastDamerauLevenshtein import damerauLevenshtein

path_alexa2k = '../datasets/alexa_top_1m.csv'


class AlexaLevenSimilarity:
    def __init__(self, path=None):
        self.__alexa2k_domains_dict = set()

        # self.alexa_toplist = set()
        with open(path_alexa2k, "r") as f:
            r = reader(f)

            for entry in r:
                # print("entry", entry)
                self.__alexa2k_domains_dict.add(entry[1])

    def score(self, domain):
        inAlexa = False
        MAX_SIMILARITY_SCORE = -1
        MAX_SIMILARITY_DOMAIN = None
        domain_name = domain.name + "." + domain.tld
        # print("checking Phish Domain name:", domain_name)
        if domain_name in self.__alexa2k_domains_dict:
            inAlexa = True
            domain.set_subscore("AlexaLevSim", {"score": inAlexa,
                                                "note": "Scored domain in alexa top 1m."})
            # return inAlexa
            return (0, inAlexa)  # NOT RISKY IT IS AN ALEXA DOMAIN
        else:
            # if it is not an alexa domain then want to give it a score of how
            # similar it is to an alexa domain
            for a_dom in self.__alexa2k_domains_dict:
                sim_score = damerauLevenshtein(a_dom, domain_name, similarity=True)
                if MAX_SIMILARITY_SCORE < sim_score:
                    MAX_SIMILARITY_SCORE = sim_score
                    MAX_SIMILARITY_DOMAIN = a_dom
            # print("Most similar good domain:", MAX_SIMILARITY_DOMAIN)
            # print("Most similar score:", MAX_SIMILARITY_SCORE)
            return MAX_SIMILARITY_SCORE, MAX_SIMILARITY_DOMAIN


# als = AlexaLevenSimilarity()

# from classes.Domain import Domain

# Testing on a single domain

'''
test_domain = Domain("000webhostapp.com", "idk", 0)
print("returned score:", als.score(test_domain))
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
