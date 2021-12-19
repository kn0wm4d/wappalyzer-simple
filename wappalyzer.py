import requests
import traceback
import sys
import json
from requests_futures.sessions import FuturesSession
from huepy import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Check a single URL.",
                    action='store')
parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="Check a list of URLs.",
                    action='store')
parser.add_argument("-s", "--source",
                    dest="source",
                    help="Name the source of the Scan.",
                    action='store')

args = parser.parse_args()

if not args.source:
    print(bad("You must provide a source! Example: (--source Inventory)"))
    sys.exit()

if not args.url and not args.usedlist:
    print(bad('Please provide either a list of URLs or an URL!'))
    sys.exit()

def get_tech(url, technologies):
    ts = {}
    search_vulns = []
    tech_list = []
    try:
        if 'RESPONSE_NOT_OK' in str(technologies):
            raise Exception
        for t in technologies['applications']:
            if t['version']:
                for category in t['categories']:
                    for category_type, category_name in category.items():
                        ts[category_name] = f'{t["name"]} {t["version"]}'
            if not t['version']:
                for category in t['categories']:
                    for category_type, category_name in category.items():
                        ts[category_name] = f'{t["name"]}'
    
    except Exception as e:
        ts = {}
    return ts, search_vulns

if __name__ == "__main__":
    urls = None
    if args.url:
        urls = [args.url]
    if args.usedlist:
        urls = [l.strip() for l in open(args.usedlist, 'r').readlines()]
    
    tech = {}
    fs = []

    session = FuturesSession(max_workers=15)
    urls_futures = []

    for u in urls:
        urls_futures.append(session.get(f'http://localhost:3000/extract?url={u}'))
    
    for f in urls_futures:

        try:
            result = f.result()
        except:
            result = None
        
        if result:
            if 'urls' in result.json().keys():
                response = result.json()
                for url in list(response['urls'].keys()):
                    if url not in tech.keys():
                        tech[url] = {}
                    ts, search_vulns = get_tech(url, response)
                    for k, v in ts.items():
                        tech[url][k] = v
                    tech[url]["Source"] = args.source
                    tech[url]['Vulnerable'] = "Safe"

    print(json.dumps(tech, indent=4))