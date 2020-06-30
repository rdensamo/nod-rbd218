from dns.resolver import query
from dns.resolver import NXDOMAIN


class Resolver:

    @staticmethod
    def score(domain):
        # TODO: Get and check TTL
        try:
            answer = query(domain.domain)
            domain.set_subscore("resolver", {"score": True})
        except NXDOMAIN:
            domain.set_subscore("resolver", {"score": False})
