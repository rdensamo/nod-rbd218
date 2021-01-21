import tldextract
from copy import deepcopy


class Domain:
    """
    Representation of an individual domain name.
    """

    def __init__(self, query, registrar, age=None):
        self._domain = query

        self.tld = None
        self.subdomain = None
        self.name = None

        parsed = tldextract.extract(self.domain)
        self.tld = parsed.suffix
        self.name = parsed.domain
        self.subdomain = parsed.subdomain

        if registrar is not None:
            self._registrar = registrar
        else:
            self._registrar = ""

        # Seconds since creation date
        self._age = age
        self.score = None
        self.subscores = dict()
        self.simplescores = dict()

        if self.domain[0:4] == "xn--":
            self.set_subscore("punycode", {"score:": True})

    def __repr__(self):
        return f"Domain({self.domain}, {self.registrar}, {self.age})"

    @property
    def domain(self):
        return self._domain

    @domain.setter
    def domain(self, d):
        self._domain = d

    @property
    def registrar(self):
        return self._registrar

    @registrar.setter
    def registrar(self, r):
        self._registrar = r

    @property
    def age(self):
        return self._age

    @age.setter
    def age(self, a):
        self._age = a

    def subscores(self):
        return deepcopy(self.subscores)

    # TODO: should probably be add_subscore, currently a breaking change
    def set_subscore(self, source, subscore):
        self.subscores[source] = subscore

    def set_simplescore(self, source, subscore):
        self.simplescores[source] = subscore

