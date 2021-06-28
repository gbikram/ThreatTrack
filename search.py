# Datasets - Shodan, Censys, Fofa, Zoomeye

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

load_dotenv()

# Initialize dataset clients
shodan_client = shodan.Shodan(os.environ.get("SHODAN_API_KEY"))
censys_ipv4_client = CensysIPv4()
otx_client = OTXv2(os.environ.get("OTX_API_KEY"))

# Parse and lookup dorks in dorks.csv
def parseDorksList():

    with open('dorks.csv', mode='r') as dorks_file:
        dorks_reader = csv.reader(dorks_file, delimiter=';')
        next(dorks_reader)

        for line in dorks_reader:
            dataset = line[0]

            # Shodan
            if(dataset == "Shodan"):
                dork_name = line[1]
                dork = line[2]
                searchShodan(dork_name, dork)
            
            # Censys
            elif(dataset == "Censys"):
                dork_name = line[1]
                dork = line[2]
                searchCensys(dork_name, dork)
            
            # ZoomEye
            elif(dataset == "Zoomeye"):
                print("zoomeye todo")


# Lookup given dork on Shodan
def searchShodan(dork_name, dork):
    print(dork)

    try:
        # Search Shodan
        results = shodan_client.search(dork)
        # Show the results
        ip_addresses = []
        for result in results['matches']:
            ip_addresses.append(result['ip_str'])
        createOtxPulse(dork_name, ip_addresses, 'Shodan')
    except shodan.APIError as e:
        print('Error: {}'.format(e))


# Lookup given dork on Censys
def searchCensys(dork_name, dork):
    ip_addresses = []
    for page in censys_ipv4_client.search('443.https.tls.certificate.parsed.subject.common_name: "Quasar Server CA"'):
        ip_addresses.append(page['ip'])
    createOtxPulse(dork_name, ip_addresses, 'Censys')


# Create OTX Pulse and add indicators
def createOtxPulse(dork_name, indicators, dataset):
    pulse_name = "Daily CnC IPs - " + dork_name + " - " + dataset + " - " + (datetime.date.today().strftime('%Y%m%d'))
    pulse_indicators = []
    pulse_tags = []
    pulse_tags.append(dork_name)
    pulse_tags.append(dataset)

    for indicator in indicators:
        pulse_indicator = {
            'indicator': indicator,
            'type': 'IPv4'
        }
        pulse_indicators.append(pulse_indicator)
    
    response = otx_client.create_pulse(name=pulse_name ,public=False ,indicators=pulse_indicators ,tags=pulse_tags , references=[])

if __name__ == "__main__":
    parseDorksList()
