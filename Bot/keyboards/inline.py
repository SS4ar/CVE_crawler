from typing import Final
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

KB_CVE_PARAMS: Final = InlineKeyboardMarkup(1)
KB_CVE_PARAMS.add(
    InlineKeyboardButton("Показать рекомендованные действия", callback_data="cve_show_actions")
)
KB_CVE_PARAMS.add(
    InlineKeyboardButton("Показать полезные ссылки", callback_data="cve_show_useful_urls")
)