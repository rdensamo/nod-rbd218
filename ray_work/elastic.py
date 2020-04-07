import requests
from requests.auth import HTTPBasicAuth
import json
import sys

URL = 'http://elastic.cc.lehigh.edu:9200'

if len(sys.argv) != 3:
        print ("Usage: python elastic.py username password")

username = sys.argv[1]
password = sys.argv[2]

j = '''{
  "version": true,
  "size": 500,
  "sort": [
    {
      "age": {
        "order": "asc",
        "unmapped_type": "boolean"
      }
    }
  ],
  "_source": {
    "excludes": []
  },
  "aggs": {
    "2": {
      "date_histogram": {
        "field": "@timestamp",
        "interval": "10s",
        "time_zone": "America/New_York",
        "min_doc_count": 1
      }
    }
  },
  "stored_fields": [
    "*"
  ],
  "script_fields": {},
  "docvalue_fields": [
    {
      "field": "@timestamp",
      "format": "date_time"
    }
  ],
  "query": {
    "bool": {
      "must": [
        {
          "query_string": {
            "query": "brotype:dns-tracker",
            "analyze_wildcard": true,
            "default_field": "*"
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": 1572881437332,
              "lte": 1572881873186,
              "format": "epoch_millis"
            }
          }
        }
      ],
      "filter": [],
      "should": [],
      "must_not": []
    }
  },
  "highlight": {
    "pre_tags": [
      "@kibana-highlighted-field@"
    ],
    "post_tags": [
      "@/kibana-highlighted-field@"
    ],
    "fields": {
      "*": {}
    },
    "fragment_size": 2147483647
  }
}'''

headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
req = requests.post('{}/_search'.format(URL), data=j, headers=headers, auth=HTTPBasicAuth(username, password))

print(req)
print(json.dumps(req.json(), sort_keys=True, indent=4, separators=(',', ': ')))