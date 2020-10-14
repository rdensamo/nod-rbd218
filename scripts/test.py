# import matplotlib.pyplot as plt
from csv import DictReader

from classes.Domain import Domain


class RedCanaryEntropy:
    def __init__(self):
        # Character frequency distribution from Alexa's top one million domain names
        self.__dom_char_freq = {'-': 0.013342298553905901, '_': 9.04562613824129e-06,
                                '0': 0.0024875471880163543,
                                '1': 0.004884638114650296, '2': 0.004373560237839663,
                                '3': 0.0021136613076357144, '4': 0.001625197496170685,
                                '5': 0.0013070929769758662,
                                '6': 0.0014880054997406921, '7': 0.001471421851820583,
                                '8': 0.0012663876593537805,
                                '9': 0.0010327089841158806, 'a': 0.07333590631143488, 'b': 0.04293204925644953,
                                'c': 0.027385633133525503, 'd': 0.02769469202658208, 'e': 0.07086192756262588,
                                'f': 0.01249653250998034, 'g': 0.038516276096631406, 'h': 0.024017645001386995,
                                'i': 0.060447396668797414, 'j': 0.007082725266242929, 'k': 0.01659570875496002,
                                'l': 0.05815885325582237, 'm': 0.033884915513851865, 'n': 0.04753175014774523,
                                'o': 0.09413783122067709, 'p': 0.042555148167356144, 'q': 0.0017231917793349655,
                                'r': 0.06460084667060655, 's': 0.07214640647425614, 't': 0.06447722311338391,
                                'u': 0.034792493336388744, 'v': 0.011637198026847418, 'w': 0.013318176884203925,
                                'x': 0.003170491961453572, 'y': 0.016381628936354975, 'z': 0.004715786426736459}

    # Simplify domain names: e.g.  “en.www.wikipedia.org” would be reduced to “enwikipedia”
    # TODO: Make sure domain names are coming in the format we expect them to

    # calculate entropy of simplified domain using relative entropy
    # pi : represents the proportion of each unique character i in input X e.g 1/5
    # qi : The above dict is the baseline distribution on non malicious domains
    # Equation: DKL(P, Q) = sum(pi*log(pi/qi))
    # Calculate entropy scores
    # TODO: is there a faster way to loop through and sum log of each character string ? - using dict above

    def score(self, domain):
        entropy_score = dict()
        simplified_domain = domain.domain
        qi = dict()
        pi = dict()
        DLK_lg = dict()
        dom_len = len(simplified_domain)
        freq_dict = dict()
        for i in self.__dom_char_freq.keys():
            freq_dict[i] = 0

        for n in simplified_domain:
            keys = freq_dict.keys()
            if n in keys:
                freq_dict[n] += 1
                pi[n] = freq_dict.get(n) / dom_len
                qi[n] = self.__dom_char_freq.get(n)
                DLK_lg[n] = (pi[n] * math.log10(pi[n])) / (qi[n])
                # DLK_lg[n] = pi[n] * math.log10(pi[n] / qi[n])
        entropy_score = sum(DLK_lg.values())
        # print("domain:", domain, "simplified_domain:", simplified_domain, "entropy: ", entropy_score)
        domain.set_subscore("domain name entropy", {"score": entropy_score,
                                                    "note": "scoring wih exact calculated entropy"})
        return -1 * entropy_score

    # TESTING FUNCTION FOR CODE BELOW:
    def testScore(self, bad_doms, good_doms):
        # bad domains
        key = 0
        zonefile_maldomains = dict()
        with open(bad_doms, "r") as f:
            for row in f:
                domain = Domain(row, "registrarexample.com", 0)
                # TODO: Should registrars and age be optional in the Domain class causes error otherwise
                zonefile_maldomains[row] = self.score(domain)

                key += 1
                if key == 10000:
                    break

        key = 0
        # good domains
        alexastopdomains = dict()
        with open(good_doms, "r") as f:

            reader = DictReader(f)
            for row in reader:
                alexa_domain = row.get("domain")
                if alexa_domain is None:
                    continue
                else:
                    domain = Domain(alexa_domain, "registrarexample.com", 0)
                    alexastopdomains[domain] = self.score(domain)
                key += 1
                if key == 10000:
                    break

        x = np.array(np.array(list(zonefile_maldomains.values())).astype(float))
        y = np.array(np.array(list(alexastopdomains.values())).astype(float))
        plt.xlabel('Entropy Value', fontsize=15)
        plt.ylabel('Frequency', fontsize=15)
        plt.title('Entropies for Legitimate and Malicious Domains', fontsize=15)
        plt.hist(x, color="red")
        plt.hist(y, color="green")
        # plt.xlim(-300)
        plt.show()
        return 0


# TESTING CODE BELOW:

'''
path1 = "../datasets/zonefile_domains_full.txt"
path2 = "../datasets/alexa_top_2k.csv"
'''

'''
# path1 = "../datasets/zonefile_domains_full.txt"
path1 = "../mal_domains/justdomains.txt"
path2 = "../datasets/alexa_top_1m.csv"

red = RedCanaryEntropy()
red.testScore(path1, path2)



red = RedCanaryEntropy()
score = red.score(Domain("qq.com", "exampleregistrar.com", 0))
print(score)
score = red.score(Domain("deutschland.de/en", "dexampleregistrar.com", 0))
print(score)
'''

# Seems to suffer from high false negatives still
# Alexa top domains contains foreign domains as well the lower down this list we read the
# more similar it is to malicious domain names
# TODO: we can also use the Country TLD to determine if it is from another country

# TODO: entropy scores above 100 for both bad domains suspicious
# TODO: Observe / Be careful of the scale on the graph - increases with more data points
# TODO: Seems like data is bad when it is good and the scale just changed
# TODO: next need to test this on foreigin good and bad domains
