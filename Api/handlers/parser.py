import requests
import json
from datetime import datetime, date


base_vuln_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
base_epss_api_url = "https://api.first.org/data/v1/epss"
base_github_Poc_url = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/"

def parse_by_Id(cveId):
    full_url = base_github_Poc_url+"/"+cveId[cveId.find("-")+1:cveId.rfind("-")]+"/"+cveId+".json"
    try:
        response = requests.request('GET', full_url, timeout=5).json()
        urls = []
        for url in response:
            urls.append(url['html_url'])
        return urls
    except:
        return None

def parse_vuln_conf(vuln_confs):
    nodes = []
    for vuln_conf in vuln_confs:
        for node in vuln_conf['nodes']:
            for cpeMatch in node['cpeMatch']:
                if cpeMatch['vulnerable'] == True:
                    nodes.append(cpeMatch['criteria'])
    return nodes

def parce_data_from_res(res, cveId):
    data_assmbly = []
    for cve in res['vulnerabilities']:
        data = {}
        tech_part = cve['cve']
        data['id'] = tech_part['id']
        cveId = tech_part['id']
        try:
            data['name'] = tech_part['cisaVulnerabilityName']
        except:
            data['name'] = None
        data['pub_date_time'] = tech_part['published']
        try:
            data['actions'] = tech_part['cisaRequiredAction']
        except:
            data['actions'] = None
        try:
            data['vendorComments'] = tech_part['vendorComments']
        except:
            data['vendorComments'] = None
        try:
            cvssv3 = tech_part['metrics']['cvssMetricV31'][0]['cvssData']
            del cvssv3['vectorString']
            data['cvss3'] = cvssv3
        except:
            data['cvss3'] = None
        try:
            cvssv2 = tech_part['metrics']['cvssMetricV2'][0]['cvssData']
            del cvssv2['vectorString']
            data['cvss2'] = cvssv2
        except:
            data['cvss2'] = None
        try:
            epss_query = {"cve": cveId}
            epss_response = requests.request('GET', base_epss_api_url, params=epss_query, timeout=5).json()
            epss_score = epss_response['data'][0]
            del epss_score['cve']
            data['epss'] = epss_score
        except:
            data['epss'] = None
        try:
            vuln_product_data = tech_part['configurations']
        except:
            vuln_product_data = None
        data['useful_urls'] = parse_by_Id(cveId)
        if vuln_product_data!=None:
            data['vuln_conf'] = parse_vuln_conf(vuln_product_data)
        data_assmbly.append(json.dumps(data))
    return data_assmbly


def convert_date(date_string):
    input_format = "%d.%m.%Y"
    output_format = "%Y-%m-%dT%H:%M:%S.%f"
    date_obj = datetime.strptime(date_string, input_format)
    converted_date = datetime.strftime(date_obj, output_format)
    return converted_date


def request_by_Id(cve_id):
    query = {"cveId": cve_id}
    epss_query = {"cve": cve_id}
    response = requests.request('GET', base_vuln_api_url, params=query, timeout=5).json()
    epss_response = requests.request('GET', base_epss_api_url, params=epss_query, timeout=5).json()
    data = parce_data_from_res(response, cve_id)
    return str(data)


def parse_ids_from_res(res):
    ids = []
    for cve in res['vulnerabilities']:
        tech_part = cve['cve']
        ids.append(tech_part['id'])
    return ids


def request_by_date(date_start, date_end):
    if date_end==None:
        date_end = datetime.now().isoformat()
    if date_start==None:
        date_start = date.today().isoformat()
    query = {"pubStartDate": str(date_start), "pubEndDate": str(date_end)}
    response = requests.request('GET', base_vuln_api_url, params=query, timeout=10).json()
    data = parse_ids_from_res(response)
    return str(data)