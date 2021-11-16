# Datasets - Shodan, Censys, Fofa, Zoomeye, URLScan

import os
from dotenv import load_dotenv
from pathlib import Path
import shodan
import pyfofa
from zoomeye.sdk import ZoomEye
from censys.search import CensysIPv4
import csv
from OTXv2 import OTXv2
import datetime
import requests
import json
import jmespath
import pandas as pd

load_dotenv()

# Initialize dataset clients
shodan_client = shodan.Shodan(os.environ.get("SHODAN_API_KEY"))
censys_ipv4_client = CensysIPv4()
otx_client = OTXv2(os.environ.get("OTX_API_KEY"))


# Parse and lookup queries in queries.csv
def parsequeriesList():

    print("Parsing Queries Dataset...")
    print()

    with open('queries.csv', mode='r') as queries_file:
        queries_reader = csv.reader(queries_file, delimiter=',')
        next(queries_reader)

        for line in queries_reader:
            dataset = line[0]
            tracking = line[3]

            # Shodan
            if(dataset == "Shodan" and tracking == "True"):
                query_name = line[1]
                query = line[2]
                searchShodan(query_name, query)
            
            # Censys
            elif(dataset == "Censys" and tracking == "True"):
                query_name = line[1]
                query = line[2]
                searchCensys(query_name, query)
            
            # ZoomEye
            elif(dataset == "Zoomeye" and tracking == "True"):
                print("zoomeye todo")
            
            # URLScan
            elif(dataset == "URLScan" and tracking == "True"):
                query_name = line[1]
                query = line[2]
                searchUrlscan(query_name, query)

            # PublicWWW
            elif(dataset == "PublicWWW" and tracking == "True"):
                query_name = line[1]
                query = line[2]
                searchPublicWWW(query_name, query)
            

# Lookup given query on Shodan
def searchShodan(query_name, query):

    print("Querying Shodan for ", query_name)

    try:
        # Search Shodan
        results = shodan_client.search(query)

        # Show the results
        ip_addresses = []
        for result in results['matches']:
            ip_addresses.append(result['ip_str'])

        if(len(ip_addresses) > 0):
            createOtxPulse(query_name, ip_addresses, 'Shodan', 'IPv4')
        else:
            print("No Results!")
            print()
    
    except shodan.APIError as e:
        print('Error: {}'.format(e))


# Lookup given query on Censys
def searchCensys(query_name, query):

    print("Querying Censys for ", query_name)

    ip_addresses = []
    for page in censys_ipv4_client.search(query):
        ip_addresses.append(page['ip'])
    if(len(ip_addresses) > 0):
        createOtxPulse(query_name, ip_addresses, 'Censys', 'IPv4')
    else:
        print("No Results!")
        print()


# Lookup given query in URLScan
def searchUrlscan(query_name, query):

    print("Querying URLScan for ", query_name)

    urlscan_api_endpoint = "https://urlscan.io/api/v1/search/"
    params = {
        "q": query
    }
    urlscan_req = requests.get(urlscan_api_endpoint, params)
    urlscan_response = urlscan_req.json()
    urlscan_urls = jmespath.search('results[].page.url', urlscan_response)
    if(len(urlscan_urls) > 0):
        createOtxPulse(query_name, urlscan_urls, 'URLScan', 'URL')
    else:
        print("No Results!")
        print()



def searchPublicWWW(query_name, query):
    publicwww_api_endpoint = "https://publicwww.com/websites/"
    params = {
        'export' : 'csvu',
        'key': os.environ.get('PUBLICWWW_KEY')
    }
    publicwww_req = requests.get(publicwww_api_endpoint + query + '/', params)
    
    content_utf = publicwww_req.content.decode('utf-8')
    csv_reader = csv.reader(content_utf.splitlines(), delimiter=';')
    csv_list = list(csv_reader)
    publicwww_indicators = []
    for row in csv_list:
        publicwww_indicators.append(row[0])
    createOtxPulse(query_name, publicwww_indicators, 'PublicWWW', 'URL')

# Create OTX Pulse and add indicators
def createOtxPulse(query_name, indicators, dataset, indicators_type):
    pulse_name = (query_name + " - " + dataset + " - " + (datetime.date.today().strftime('%Y%m%d')))
    pulse_indicators = []
    pulse_tags = []
    pulse_tags.append(query_name)
    pulse_tags.append(dataset)

    for indicator in indicators:
        pulse_indicator = {
            'indicator': indicator,
            'type': indicators_type
        }
        pulse_indicators.append(pulse_indicator)
    
    response = otx_client.create_pulse(name=pulse_name ,public=False ,indicators=pulse_indicators ,tags=pulse_tags , references=[])
    print("Pulse Created: ",pulse_name)
    print()

if __name__ == "__main__":
    parsequeriesList()
