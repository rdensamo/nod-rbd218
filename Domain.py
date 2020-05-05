class Domain:
    """

    """
    def __init__(self, query, registrar, age):
        self.domain = query
        self.registrar = registrar
        self.age = age
        self.score = None

    def __str__(self):
        return "Domain({}, {}, {})".format(self.domain, self.registrar, self.age)

    def get_domain(self):
        return self.domain

    def get_registrar(self):
        return self.registrar

    def get_age(self):
        return self.age

    def get_score(self):
        return self.score

