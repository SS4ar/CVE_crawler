import requests
import json

import Bot.config


class CVE:
    def __init__(self, parsed_data):
        print(parsed_data)
        parsed_data = parsed_data[0]
        print(parsed_data)
        self.actions = parsed_data['actions']
        self.cvss2 = parsed_data['cvss2']
        self.cvss3 = parsed_data['cvss3']
        self.epss = parsed_data['epss']
        self.id = parsed_data['id']
        self.name = parsed_data['name']
        self.pub_date_time = parsed_data['pub_date_time']
        self.useful_urls = parsed_data['useful_urls']
        self.vendorComments = parsed_data['vendorComments']
        self.vuln_conf = parsed_data['vuln_conf']

    def __str__(self):
        return f"Vulnerability ID: {self.id} with Name: {self.name}"

    def convert_to_json(self):
        cve_dict = {
            'actions': self.actions,
            'cvss2': self.cvss2,
            'cvss3': self.cvss3,
            'epss': self.epss,
            'id': self.id,
            'name': self.name,
            'pub_date_time': self.pub_date_time,
            'useful_urls': self.useful_urls,
            'vendorComments': self.vendorComments,
            'vuln_conf': self.vuln_conf
        }
        json_string = json.dumps(cve_dict, indent=4)
        return json_string


class CVEFinder:
    def __init__(self):
        self.base_url = Bot.config.API_URL

    def __request_from_parser(self, cve_id) -> str:
        url = self.base_url + cve_id
        response = requests.get(url)
        return response.text

    def get_by_id(self, cve_id) -> CVE:
        response_data = self.__request_from_parser(cve_id)
        parsed_data = json.loads(response_data)
        cve = CVE(parsed_data)
        return cve
