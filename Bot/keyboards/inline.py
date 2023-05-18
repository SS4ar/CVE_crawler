from typing import Final
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.utils.callback_data import CallbackData

from Bot.utils.cve_finder import CVEFinder, CVE

cve_callbacks = CallbackData("vote", "action", "cve")
subscription_callbacks = CallbackData("vote", "action")


class CVECallbackActionsStatus:
    def __init__(self,
                 recommended_actions: bool = False,
                 severity_2x: bool = False,
                 severity_3x: bool = False,
                 epss_rating: bool = False,
                 useful_urls: bool = False,
                 affected_configs: bool = False,
                 vendor_comments: bool = False,
                 ):
        self.vendor_comments = vendor_comments
        self.affected_configs = affected_configs
        self.useful_urls = useful_urls
        self.epss_rating = epss_rating
        self.severity_3x = severity_3x
        self.severity_2x = severity_2x
        self.recommended_actions = recommended_actions


class SubscriptionCallbackStatus:
    def __init__(self,
                 subscription_enabled: bool = False,
                 subscription_disables: bool = False,
                 key_word: bool = False,
                 cvss_minimum_rating: bool = False):
        self.subscription_enabled = subscription_enabled
        self.subscription_disables = subscription_disables
        self.key_word = key_word
        self.cvss_minimum_rating = cvss_minimum_rating


def get_cve_keyboard(cve: CVE, callback_actions_status: CVECallbackActionsStatus = CVECallbackActionsStatus()):
    kb_cve_params = InlineKeyboardMarkup(1)
    if not callback_actions_status.recommended_actions:
        kb_cve_params.add(
            InlineKeyboardButton('Рекомендованные действия',
                                 callback_data=cve_callbacks.new(action="cve_show_actions", cve=cve.id))
        )
    if not callback_actions_status.severity_2x:
        kb_cve_params.add(
            InlineKeyboardButton('Оценка при CVSS 2.0',
                                 callback_data=cve_callbacks.new(action="cve_show_severity2x", cve=cve.id))
        )

    if not callback_actions_status.severity_3x:
        kb_cve_params.add(
            InlineKeyboardButton('Оценка при CVSS 3.x',
                                 callback_data=cve_callbacks.new(action="cve_show_severity3x", cve=cve.id))
        )

    if not callback_actions_status.epss_rating:
        kb_cve_params.add(
            InlineKeyboardButton('EPSS Рейтинг',
                                 callback_data=cve_callbacks.new(action="cve_show_epss_rating", cve=cve.id))
        )

    if not callback_actions_status.useful_urls:
        kb_cve_params.add(
            InlineKeyboardButton('Полезные ссылки',
                                 callback_data=cve_callbacks.new(action="cve_show_useful_urls", cve=cve.id))
        )
    return kb_cve_params


def get_subscription_keyboard(callback_subscription_status: SubscriptionCallbackStatus = SubscriptionCallbackStatus()):
    kb_subscription_params = InlineKeyboardMarkup(1)

    if not callback_subscription_status.subscription_enabled:
        kb_subscription_params.add(
            InlineKeyboardButton('✅ Включить подписку',
                                 callback_data=subscription_callbacks.new(action="sub_enable"))
        )
    if not callback_subscription_status.subscription_disables:
        kb_subscription_params.add(
            InlineKeyboardButton('❌ Отключить подписку',
                                 callback_data=subscription_callbacks.new(action="sub_disable"))
        )
    if not callback_subscription_status.key_word:
        kb_subscription_params.add(
            InlineKeyboardButton('Указать ключевое слово',
                                 callback_data=subscription_callbacks.new(action="sub_set_keyword"))
        )
    if not callback_subscription_status.cvss_minimum_rating:
        kb_subscription_params.add(
            InlineKeyboardButton('Указать минимальный рейтинг',
                                 callback_data=subscription_callbacks.new(action="sub_set_min_rating"))
        )

    return kb_subscription_params
