import requests
import json

import Bot.config
from Bot.utils.translator import TextTranslation


class CVE:
    def __init__(self, parsed_data):
        print(parsed_data)
        parsed_data = parsed_data[0]
        print(parsed_data)
        self.actions = str(parsed_data['actions'])
        self.cvss2 = parsed_data['cvss2']
        self.cvss3 = parsed_data['cvss3']
        self.epss = parsed_data['epss']
        self.id = str(parsed_data['id'])
        self.name = str(parsed_data['name'])
        self.pub_date_time = str(parsed_data['pub_date_time'])
        self.useful_urls = parsed_data['useful_urls']
        self.vendorComments = str(parsed_data['vendorComments'])
        # self.vuln_conf = parsed_data['vuln_conf']

    def __str__(self):
        return f"Vulnerability ID: {self.id} with Name: {self.name}"

    def convert_to_json(self) -> str:
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
            # 'vuln_conf': self.vuln_conf
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
        if len(parsed_data) == 0:
            raise FileNotFoundError
        cve = CVE(parsed_data)
        return cve


class CVEMessageFormatter:
    def __init__(self, cve: CVE):
        self.cve = cve

    def get_base_message(self) -> str:
        base_message = f"<b>✅ Уязвимость найдена!</b>\n\n" \
                       f"<b><u>{self.cve.id}</u></b>\n" \
                       f"🕐 Дата публикации: {self.cve.pub_date_time}\n\n" \
                       f"🇺🇸 Описание на EN: {self.cve.name}\n\n" \
                       f"🇷🇺 Описание на RU: {TextTranslation().translate(text=self.cve.name)}"
        return base_message

    def get_recommended_actions(self) -> str:
        recommended_actions = f"\n\n<b>Рекомендованные действия:</b>\n" \
                              f"<b>EN:</b> {self.cve.actions}\n" \
                              f"<b>RU:</b> {TextTranslation().translate(text=self.cve.actions)}"
        return recommended_actions

    def get_severity2x(self) -> str:
        if self.cve.cvss2 is None:
            return "\n\n<b>Оценка строгости и метрика при CVSS 2.0 отсутствует.</b>"

        severity2x = f"\n\n<b><u>Оценка строгости и метрика при CVSS 2.0:</u></b>\n" \
                     f"<b>Способ получения доступа (AV): </b>{self.cve.cvss2['accessVector']}\n" \
                     f"<b>Сложность получения доступа (AC): </b>{self.cve.cvss2['accessComplexity']}\n" \
                     f"<b>Аутентификация (Au): </b>{self.cve.cvss2['authentication']}\n\n" \
                     f"" \
                     f"<b>Влияние на конфиденциальность (C): </b>{self.cve.cvss2['confidentialityImpact']}\n" \
                     f"<b>Влияние на целостность (I): </b>{self.cve.cvss2['integrityImpact']}\n" \
                     f"<b>Влияние на доступность (A): </b>{self.cve.cvss2['availabilityImpact']}\n\n" \
                     f"" \
                     f"<b>Базовая оценка (BS): {self.cve.cvss2['baseScore']}</b>\n" \
                     f"Версия CVSS: {self.cve.cvss2['version']}\n"
        return severity2x

    def get_severity3x(self) -> str:
        if self.cve.cvss3 is None:
            return "\n\n<b>Оценка строгости и метрика при CVSS 3.1 отсутствует.</b>"

        severity2x = f"\n\n<b><u>Оценка строгости и метрика при CVSS 3.1:</u></b>\n" \
                     f"<b>Вектор атаки (AV): </b>{self.cve.cvss3['attackVector']}\n" \
                     f"<b>Сложность атаки (AC): </b>{self.cve.cvss3['attackComplexity']}\n" \
                     f"<b>Уровень привилегий (PR): </b>{self.cve.cvss3['privilegesRequired']}\n" \
                     f"<b>Взаимодействие с пользователем (UI): </b>{self.cve.cvss3['userInteraction']}\n" \
                     f"<b>Влияние на другие компоненты системы (S): </b>{self.cve.cvss3['scope']}\n\n" \
                     f"" \
                     f"<b>Влияние на конфиденциальность (C): </b>{self.cve.cvss3['confidentialityImpact']}\n" \
                     f"<b>Влияние на целостность (I): </b>{self.cve.cvss3['integrityImpact']}\n" \
                     f"<b>Влияние на доступность (A): </b>{self.cve.cvss3['availabilityImpact']}\n\n" \
                     f"" \
                     f"<b>Базовая оценка (BS): {self.cve.cvss3['baseScore']}</b>\n" \
                     f"<b>Базовая серьезность (BS): {self.cve.cvss3['baseSeverity']}</b>\n" \
                     f"Версия CVSS: {self.cve.cvss3['version']}\n"
        return severity2x

    def get_epss_rating(self) -> str:
        if self.cve.epss is None:
            return "\n\n<b>Оценка EPSS отсутствует.</b>"

        epss_rating = f"\n\n<b>Рейтинг EPSS:</b>\n" \
                      f"<b>Дата оценки:</b> {self.cve.epss['date']}\n" \
                      f"<b>EPSS:</b> {self.cve.epss['epss']}\n" \
                      f"<b>Процентно:</b> {round(float(self.cve.epss['percentile']) * 100, 2)}%\n"
        return epss_rating

    def get_useful_urls(self) -> str:
        if self.cve.useful_urls is None:
            return "\n\n<b>Полезные ссылки отсутствуют.</b>"

        useful_urls = f"\n\n<b>Полезные ссылки:</b>\n"
        for url in self.cve.useful_urls:
            useful_urls += f"{url}\n"

        return useful_urls
