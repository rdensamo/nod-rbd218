class SpamhausReg:
    def __init__(self):
        # taken from: https://www.spamhaus.org/statistics/registrars/
        # This has to be processed by hand, spamhaus does not list registrars
        # by the value they serve in whois, nor by their name as registered
        # with ICANN
        self.__spamhaus_reg = {
            "todaynic": {"badnessIndex": 7.45, "percentBadDomains": .834},
            "厦门纳网科技股份有限公司": {"badnessIndex": 4.55, "percentBadDomains": .507},
            "shinjiru": {"badnessIndex": 3.96, "percentBadDomains": .592},
            "GMO": {"badnessIndex": 3.96, "percentBadDomains": .327},
            "r01": {"badnessIndex": 2.59, "percentBadDomains": .331},
            "alibaba": {"badnessIndex": 2.09, "percentBadDomains": .246},
            "ename technology": {"badnessIndex": 1.92, "percentBadDomains": .227},
            "hongkong domain": {"badnessIndex": 1.88, "percentBadDomains": .307},
            "郑州世纪创联电子科技开发有限公司": {"badnessIndex": 1.60, "percentBadDomains": .230},
            "dynadot": {"badnessIndex": 1.41, "percentBadDomains": .156}
        }

    def score(self, domain):
        for reg in self.__spamhaus_reg.keys():
            if reg in domain.registrar:
                domain.set_subscore("spamhausreg", {"score": self.__spamhaus_reg[reg].get("badnessIndex", 0)})