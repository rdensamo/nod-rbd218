import tldextract
from copy import deepcopy

class Domain:
    """
    Representation of an individual domain name.
    """
    def __init__(self, query, registrar, age):
        self.domain = query

        self.tld = None
        self.subdomain = None
        self.name = None

        parsed = tldextract.extract(self.domain)
        self.tld = parsed.suffix
        self.name = parsed.domain
        self.subdomain = parsed.subdomain

        self.registrar = registrar
        # Seconds since creation date
        self.age = age
        self.score = None
        self.subscores = dict()

        if self.domain[0:4] == "xn--":
            self.set_subscore("punycode", {"score:": True})

    def __repr__(self):
        return f"Domain({self.domain}, {self.registrar}, {self.age})"

    @property
    def domain(self):
        return self.domain
    
    @domain.setter
    def domain(self, d):
        self.domain = d

    @property
    def registrar(self):
        return self.registrar

    @registrar.setter
    def registrar(self, r):
        self.registrar = r

    @property
    def age(self):
        return self.age

    @age.setter
    def age(self, a):
        self.age = a

    def subscores(self):
        return deepcopy(self.subscores)

    # TODO: should probably be add_subscore, currently a breaking change
    def set_subscore(self, source, subscore):
        self.subscores[source] = subscore


