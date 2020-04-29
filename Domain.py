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
