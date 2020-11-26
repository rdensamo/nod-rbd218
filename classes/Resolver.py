from bisect import bisect_left

from dns.resolver import query
from dns.resolver import NXDOMAIN, Timeout
from netaddr import IPNetwork, IPAddress
from netaddr.core import AddrFormatError
from requests import get


class Resolver:
    # Score is a boolean value
    ttl_intervals = (0, 1, 10, 100, 300, 900)

    def __init__(self):

        try:
            # Fetch the file, clean it up, and split it into a list.
            bogon_file = get("https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt").content
            bogon_file = bogon_file.strip()
            bogon_file = bogon_file.split(b"\n")
            # Decode the bytearrays into regular strings
            bogon_file = map((lambda s: s.decode('utf-8')), bogon_file)
            # Discard any comment lines
            bogon_file = filter((lambda l: l[0] != '#'), bogon_file)
            # Convert all the strings into IPNetworks and tuple-ify it.
            self.bogon_networks = tuple(map(IPNetwork, bogon_file))
        except:
            # If the above dies for some reason, fallback to this less comprehensive
            # predefined list of bogons from the IPv4 spec.
            self.bogon_networks = (
                IPNetwork("0.0.0.0/8"),
                IPNetwork("10.0.0.0/8"),
                IPNetwork("100.64.0.0/10"),
                IPNetwork("127.0.0.0/8"),
                IPNetwork("169.254.0.0/16"),
                IPNetwork("172.16.0.0/12"),
                IPNetwork("192.0.0.0/24"),
                IPNetwork("192.0.2.0/24"),
                IPNetwork("192.168.0.0/16"),
                IPNetwork("198.18.0.0/15"),
                IPNetwork("198.51.100.0/24"),
                IPNetwork("203.0.113.0/24"),
                IPNetwork("224.0.0.0/3"),
            )

    def _bogon_binsearch(self, ip, low, high):
        if high >= low:
            m = (low + high) // 2

            if ip in self.bogon_networks[m]:
                return True
            elif ip < self.bogon_networks[m]:
                return self._bogon_binsearch(ip, low, m - 1)
            else:
                return self._bogon_binsearch(ip, m + 1, high)
        else:
            return False

    def is_bogon(self, ip):
        return self._bogon_binsearch(ip, 0, len(self.bogon_networks))

    def score(self, domain):
        result = False
        try:
            # Query domain
            answer = query(domain.domain)
            domain.set_subscore("resolves", {"score": True})
            result = True
            # Score TTL
            # Bisect returns the offset in an iterable at which a value should
            # be inserted to keep the list sorted. In this case, it'll return
            # a value between 0 and len(ttl_intervals) that represents which
            # implicit interval it resides in.
            ttl_risk = len(Resolver.ttl_intervals) - bisect_left(Resolver.ttl_intervals, answer.rrset.ttl)
            # ttl_risk lower values are more risky
            domain.set_subscore("ttl", {"score": ttl_risk})

            # Check for bogons
            for record in answer.rrset.items:
                try:
                    ip = IPAddress(record.address)
                    result = True
                except AddrFormatError:
                    # guard against potential non-IP records (e.g. TXT)
                    ip = None
                    result = False
                domain.set_subscore("bogon", {"score": self.is_bogon(ip)})


        except Exception as e:
            result = False
            domain.set_subscore("resolves", {"score": False,
                                             "note:": e})
        # TODO: Create result dictionary that you can access or python supports mulple returns ?
        return result