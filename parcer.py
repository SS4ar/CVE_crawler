import requests

base_vuln_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
base_epss_api_url = "https://api.first.org/data/v1/epss"
base_github_Poc_url = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/"

def parse_by_Id(cveId):
    full_url = base_github_Poc_url+"/"+cveId[cveId.find("-")+1:cveId.rfind("-")]+"/"+cveId+".json"
    response = requests.request('GET', full_url, timeout=5).json()
    urls = []
    for url in response:
        urls.append(url['html_url'])
    return urls

def parse_vuln_conf(vuln_confs):
    nodes = []
    for vuln_conf in vuln_confs:
        for node in vuln_conf['nodes']:
            for cpeMatch in node['cpeMatch']:
                if cpeMatch['vulnerable'] == True:
                    nodes.append(cpeMatch['criteria'])
    return(nodes)

def request_by_Id(cveId):
    data = {}
    query = {"cveId": cveId}
    epss_query = {"cve": cveId}
    response = requests.request('GET', base_vuln_api_url, params=query, timeout=5).json()
    epss_response = requests.request('GET', base_epss_api_url, params=epss_query, timeout=5).json()
    tech_part = response['vulnerabilities'][0]['cve']
    data['id'] = tech_part['id']
    data['name'] = tech_part['cisaVulnerabilityName']
    data['pub_date_time'] = tech_part['published'] 
    data['actions'] = tech_part['cisaRequiredAction']
    try:
        data['vendorComments'] = tech_part['vendorComments']
    except:
        KeyError
    cvssv3 = tech_part['metrics']['cvssMetricV31'][0]['cvssData']
    del cvssv3['vectorString']
    data['cvss3'] = cvssv3
    cvssv2 = tech_part['metrics']['cvssMetricV2'][0]['cvssData']
    del cvssv2['vectorString']
    data['cvss2'] = cvssv2
    epss_score = epss_response['data'][0]
    del epss_score['cve']
    data['epss'] = epss_score
    vuln_product_data = tech_part['configurations']
    data['useful_urls'] = parse_by_Id(cveId)
    data['vuln_conf'] = parse_vuln_conf(vuln_product_data)
    print(data)
request_by_Id("CVE-2021-44228")
