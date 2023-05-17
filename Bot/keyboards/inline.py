from typing import Final
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.utils.callback_data import CallbackData

from Bot.utils.cve_finder import CVEFinder, CVE

cve_callbacks = CallbackData("vote", "action", "cve")


def get_cve_keyboard(cve: CVE):
    return InlineKeyboardMarkup(1).row(
        InlineKeyboardButton('Показать рекомендованные действия', callback_data=cve_callbacks.new(action="cve_show_actions", cve=cve)),
        InlineKeyboardButton('Показать полезные ссылки', callback_data=cve_callbacks.new(action="cve_show_useful_urls", cve=cve))
    )
