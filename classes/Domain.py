import tldextract


class Domain:
    """

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
        self.age = age
        self.score = None
        self.subscores = dict()

    def __repr__(self):
        return "Domain({}, {}, {})".format(self.domain, self.registrar, self.age)

    def get_domain(self):
        return self.domain

    def get_registrar(self):
        return self.registrar

    def get_age(self):
        return self.age

    def get_score(self):
        return self.score

    def set_subscore(self, source, subscore):
        self.subscores[source] = subscore
