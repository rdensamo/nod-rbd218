# Generates a list of strings that could be used to squat the lehigh.edu domain with urlcrazy.
from subprocess import check_output
from csv import reader
from io import StringIO

urlcrazy_bin = "ruby urlcrazy"  # Change 'urlcrazy' to direct path to urlcrazy script if not on path
outfile = "/path/to/nod/datasets/lehigh-typostrings.txt"


def get_urlcrazy_csv_as_reader(d, urlcrazy_bin):
    cmd = f"{bin} -f csv -r -i {d}"
    out = reader(StringIO(check_output(cmd, shell=True).decode('utf-8')))
    next(out)  # discard empty line from urlcrazy output
    next(out)  # discard header line
    return out


lu_base = get_urlcrazy_csv_as_reader("lehigh.edu", urlcrazy_bin)

strs = []

ctr = 0
for row in lu_base:
    if row[0] != "Wrong TLD" and row[0] != "All SLD":
        tmp = row[1].partition(".")[0] # Fetch only the typo information
        strs.append(tmp)

with open(outfile, "w") as f:
    for line in strs:
        f.write(f"{line}\n")