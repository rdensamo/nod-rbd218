from csv import DictReader

from classes.Domain import Domain


class DomainToolsRegistrars:

    def __init__(self, path):
        self.__dom_tools_regs = dict()

        with open(path, "r") as f:
            reader = DictReader(f)
            for row in reader:
                self.__dom_tools_regs[row['Registrar']] = row['Percent']

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
            domain.set_subscore("domaintoolsregistrars", {"score": None, "note": "Registrar price info not found"})
            return False

        domain.set_subscore("domaintoolsregistrars", {"score": self.__dom_tools_regs[real_reg]})
        # print("value is ", self.__dom_tools_regs[real_reg])
        return self.__dom_tools_regs[real_reg]




# For Testing
'''
path = "../datasets/domaintools_registrars.csv"
domain = Domain("exampledomain.com", "GoDaddy.com, LLC", 0)
domtools = DomainToolsRegistrars(path)
domtools.score(domain)
'''

