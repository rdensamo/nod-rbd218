from csv import DictReader

from classes.Domain import Domain


class DomainToolsRegistrars:

    def __init__(self, path):
        self.__dom_tools_regs = dict()
        # TODO: Do something with False Bool scores.
        self.MAX_DOMTOOL_SCORE = 8.94

        with open(path, "r") as f:
            reader = DictReader(f)
            for row in reader:
                self.__dom_tools_regs[row['Registrar']] = float(row['Percent'])

    def score(self, domain):
        # Check if registrar is in our list
        real_reg = None

        for registrar in self.__dom_tools_regs.keys():
            if domain.registrar is not None:
                # for each registrar in our collection checks if it is a substring of the registrar we
                # are scoring currently
                if registrar.lower() in domain.registrar.lower():
                    real_reg = registrar
                    break

        if real_reg is None:
           # replaced this line from False to .6
           # TODO: find a better solution to missing values
            domain.set_subscore("domaintoolsregistrars", {"score": 0.6, "note": "Registrar price info not found"})
            return 0.6

        domain.set_subscore("domaintoolsregistrars", {"score": self.__dom_tools_regs[real_reg]})
        # print("value is ", self.__dom_tools_regs[real_reg])

        # returns a normalized score for domain tools
        return self.__dom_tools_regs[real_reg] / self.MAX_DOMTOOL_SCORE




# For Testing
'''
path = "../datasets/domaintools_registrars.csv"
domain = Domain("exampledomain.com", "GoDaddy.com, LLC", 0)
domtools = DomainToolsRegistrars(path)
domtools.score(domain)
'''

