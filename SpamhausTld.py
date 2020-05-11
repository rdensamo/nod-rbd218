from csv import DictReader

class SpamhausTld:
    def __init__(self, path):
        self.__spamhaus_tlds = dict()
        with open(path, "r") as f:
            reader = DictReader(f)
            for row in reader:
                self.__spamhaus_tlds[row["tld"]] = row

    def score(self, domain):
        entry = self.__spamhaus_tlds.get(domain.tld, None)
        score = dict()

        try:
            score["score"] = entry.get("score", None)
        except AttributeError as e:
            score["score"] = None

        domain.set_subscore("SpamhausTld", score)
