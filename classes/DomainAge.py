from bisect import bisect_left


class DomainAge:
    # Approximated from the charts on page 4 and 5 of
    # https://www.domaintools.com/content/The_DmainTools_Report_Distribution_Malicious_Domain.pdf
    intervals_mo = range(0, 84, 3)
    intervals_mo_lookup = (1.45, 1.80, 3.60, 3.85, 2.10, 1.65, 1.10, 0.90, 0.40, 0.42,
                           0.49, 0.39, 0.30, 0.28, 0.31, 0.39, 0.29, 0.14, 0.20, 0.19,
                           0.18, 0.17, 0.15, 0.15, 0.14, 0.20, 0.19, 0.09)

    @staticmethod
    def score(domain):
        if domain.age < 34560:
            # First 24 days of life are most suspicious
            domain.set_subscore("age", {"score": 4.0})
        else:
            # Otherwise defer to the domaintools research
            # FIXME: This is totally wrong, should look up the offset and get its value, instead it's
            # looking up the value based on age in months, which will always be larger than all values in
            # the table.
            months = domain.age / 43800
            score = DomainAge.intervals_mo_lookup[bisect_left(DomainAge.intervals_mo, months)]
            domain.set_subscore("age", {"score": score})