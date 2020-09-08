from csv import reader

class AlexaTop:

    def __init__(self, alexa_toplist_path):
        self.alexa_toplist = set()
        with open(alexa_toplist_path, "r") as f:
            r = reader(f)

            for entry in r:
                self.alexa_toplist.add(entry[1])


    def score(self, domain):
        if domain.name + "." + domain.tld in self.alexa_toplist:
            domain.set_subscore("alexatop", {"score": True,
                                "note": "Scored domain in alexa top 1m."})
        else:
            domain.set_subscore("alexatop", {"score": False,
                                "note": "Scored domain not in alexa top 1m."})
