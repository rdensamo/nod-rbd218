from urllib import parse
from csv import DictReader


class Registrarprices:
    """

    """

    def __init__(self, path):
        self.avg_prices = dict()
        with open(path, "r") as f:

            reader = DictReader(f)

            for row in reader:
                registrar = row["Registrar"]
                if row["Average_Price"] in [None, ""]:
                    break

                # TODO: Double check if this needs to be optimized
                pt_entry = row

                entry_price = row["Average_Price"]
                self.avg_prices[registrar] = float(entry_price)

        sorted_price = list(self.avg_prices.values())
        sorted_price.sort(reverse=True)
        max_price = float(sorted_price[0])

        for key in self.avg_prices.keys():
            scaled_prices = dict(ave_price=float(self.avg_prices[key]),
                                 scaled_price= 1 - float(self.avg_prices[key]) / max_price)
            '''
            print("\n key", key)
            print("score 1", float(self.avg_prices[key]) / max_price)
            print("score 2", 1 - float(self.avg_prices[key]) / max_price)
            '''
            # Overwriting with new scaled and original price
            self.avg_prices[key] = scaled_prices

    def score(self, domain):
        # Check if registrar is in our list
        real_reg = None

        for registrar in self.avg_prices.keys():
            if domain.registrar is not None:
                # for each registrar in our collection checks if it is a substring of the registrar we
                # are scoring currently
                if registrar.lower() in domain.registrar.lower():
                    real_reg = registrar
                    break

        # print(self.avg_prices[real_reg])
        if real_reg is None:
            domain.set_subscore("registrar_prices", {"score": 0.6, "note": "Registrar price info not found"})
            return 0.6
        domain.set_subscore("registrar_prices", {"score": self.avg_prices[real_reg]["scaled_price"],
                                                 "note": "scoring with scaled registrar prices"})
        return self.avg_prices[real_reg]["scaled_price"]

# TODO: Coverage using counter to see how many domains scored
# TODO: We substring the registrar on the domain looking for key from average_prices dict

''' 
reg = Registrarprices("../TLD_PRICING/TLD_PRICES_AVGBYREG.csv")

from classes.Domain import Domain
test_domain = Domain("schoolbulletinboards.net", "GoDaddy.com", 0)
print("returned score:", reg.score(test_domain))
'''