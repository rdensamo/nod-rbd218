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
        # Try to get an entry from the domaintools hashmap using
        # domain as the key.
        # TODO: Return actual score instead of just checking for presence
        entry = self.__dom_tools_regs.get(domain.registrar, None)
        '''
        # For Testing 
        value = "domaintoolsregistrars",
        {"score": (entry is not None)}
        print(entry)
        '''
        domain.set_subscore("domaintoolsregistrars",
                            {"score": (entry is not None)})



# For Testing
'''
path = "../datasets/domaintools_registrars.csv"
domain = Domain("exampledomain.com", "GoDaddy.com, LLC", 0)
domtools = DomainToolsRegistrars(path)
domtools.score(domain)
'''
