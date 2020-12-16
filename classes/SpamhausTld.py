from csv import DictReader


class SpamhausTld:
    def __init__(self, path):
        self.__spamhaus_tlds = dict()
        self.MAX_SPAMTLD_SCORE = -1
        with open(path, "r") as f:
            reader = DictReader(f)
            for row in reader:
                # print(row)
                self.__spamhaus_tlds[row["tld"]] = row
                if float(row.get("score")) > self.MAX_SPAMTLD_SCORE:
                    self.MAX_SPAMTLD_SCORE = float(row.get("score"))
        # print(self.MAX_SPAMTLD_SCORE)

    def score(self, domain):
        entry = self.__spamhaus_tlds.get(domain.tld, None)
        score = dict()

        try:
            score["score"] = entry.get("score", None)
            result = float(entry.get("score", None)) / self.MAX_SPAMTLD_SCORE
        except AttributeError as e:
            score["score"] = None
            result = False

        if score is None or result is False:
            # replaced this line from False to .6
            # TODO: find a better solution to missing values
            score = 0.6
            domain.set_subscore("SpamhausTld", score)
            return score

        domain.set_subscore("SpamhausTld", score)
        return result


'''

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
        return (-1 * entropy_score) / self.MAX_ENTROPY_SCORE

    # TESTING FUNCTION FOR CODE BELOW:
    def testScore(self, bad_doms, good_doms, dom_size=10000):
        # bad domains
        key = 0
        malicious_domains = dict()
        with open(bad_doms, "r") as f:
            for row in f:
                domain = Domain(row, "registrarexample.com", 0)
                # TODO: Should registrars and age be optional in the Domain class causes error otherwise
                malicious_domains[row] = self.score(domain)


                key += 1
                if key == dom_size:
                    break
        #print(key)
        # to make sure we are graphing equal number of bad to good domains on the histogram
        if dom_size > key: dom_size = key

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
                if key == dom_size:
                    break

        x = np.array(np.array(list(malicious_domains.values())).astype(float))
        y = np.array(np.array(list(alexastopdomains.values())).astype(float))
        plt.xlabel('Entropy Value', fontsize=10)
        plt.ylabel('Frequency', fontsize=10)
        plt.title('Entropy for Alexa Top 1 Million and phish Domains top 10000 domains full', fontsize=10)
        plt.hist(x, color="red")
        plt.hist(y, color="green")
        # plt.xlim(0, 1)
        path = r'../graphs/Entropy Graphs/Entropy for phish Domains and Alexa Top 1 million Domains w 10000 domains full.png'
        plt.savefig(path)
        # plt.xlim(-300)
        plt.show()
        return 0
'''
