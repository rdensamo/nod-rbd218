class LehighTypoSquat:
    def __init__(self, namesquat_path):
        self.typos = None
        with open(namesquat_path, "r") as f:
            self.typos = map(lambda s: s.strip(), f.readlines())

    def score(self, domain):

        found_typo = False
        for typo in self.typos:
            if typo in domain.domain:
                found_typo = True
                break

        if found_typo:
            domain.set_subscore("lehigh-typosquat", {"score": True,
                                                     "note": "Scored domain contains 'lehigh' or a possible typo."})
            return True
        else:
            domain.set_subscore("lehigh-typosquat", {"score": False,
                                "note": "Scored domain does not contain 'lehigh' or a lehigh typo."})
            return False
