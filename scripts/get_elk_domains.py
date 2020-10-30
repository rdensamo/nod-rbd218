from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q
import json
from pprint import pprint
from classes import Domain

ES_SOCKET = "127.0.0.1:9200"

# Create elasticsearch object,
es = Elasticsearch([ES_SOCKET])

# Build query using lucene query string
query = Q("query_string",
          query="brotype:dns-tracker AND _exists_:age")

# Only get domains from the 2020.04.29 BRO index
search = Search(using=es, index="bro-*")

# Execute the query
res = search.query(query)

# Get results from ES one at a time, parse into Domain objects, add objects
# to domains.

documents = list()

for hit in res.scan():
    current_domain = Domain.Domain(getattr(hit, "query", None),
                                   getattr(hit, 'registrar', None),
                                   getattr(hit, "age", None))
    documents.append(current_domain.__dict__)

with open("../script_results/All_ES_domains_1026.json", "w") as f:
    f.write(json.dumps(documents))


# to load the file from disk
"""
data = None
with open("hits.json", "w") as f:
    data = json.loads(f.read())

"""