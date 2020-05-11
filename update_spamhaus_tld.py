from csv import writer
from time import sleep

from bs4 import BeautifulSoup
from requests import get

source_url = "https://www.spamhaus.org/statistics/tlds/"
api_base = "https://www.spamhaus.org/statistics/checktld/"

html = get(source_url)

soup = BeautifulSoup(html.content, "html5lib")

# Get the value from each option and discard any empty values.
tlds = filter(lambda val: val != "",
              map(lambda opt: opt["value"],
                  soup.findAll("option")
                  )
              )

with open('./datasets/spamhaus_tlds.csv', 'w', newline='') as csvfile:
    writer = writer(csvfile)
    writer.writerow(['tld', 'badness_percent', 'score'])
    for tld in tlds:
        res = get(api_base + tld)
        tok = res.content.decode("utf-8").split()
        writer.writerow([tok[0], tok[2][0:-1], tok[5][0:-1]])
        # Be nice to spamhaus.org
        sleep(1)
