from typing import Final
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton

KB_START_BOT: Final = ReplyKeyboardMarkup(row_width=1, resize_keyboard=True)
KB_START_BOT.add(KeyboardButton(text="✅ Запустить бота"))

KB_STOP_BOT: Final = ReplyKeyboardMarkup(row_width=1, resize_keyboard=True)
KB_STOP_BOT.add(KeyboardButton(text="❌ Остановить бота"))

KB_GOTO_MENU: Final = ReplyKeyboardMarkup(row_width=1, resize_keyboard=True)
KB_GOTO_MENU.add(KeyboardButton(text="ℹ️ Показать меню"))

KB_BACK_TO_MENU: Final = ReplyKeyboardMarkup(row_width=1, resize_keyboard=True)
KB_BACK_TO_MENU.add(KeyboardButton(text="⬅️ Назад в меню"))

KB_MAIN_MENU: Final = ReplyKeyboardMarkup(row_width=1, resize_keyboard=True)
KB_MAIN_MENU.add(KeyboardButton(text="🔍 Поиск уязвимостей"))
KB_MAIN_MENU.add(KeyboardButton(text="🔔 Подписка на уведомления"))
KB_MAIN_MENU.add(KeyboardButton(text="👤 Профиль"))

VULN_FINDER_MENU: Final = ReplyKeyboardMarkup(row_width=1, resize_keyboard=True)
VULN_FINDER_MENU.add(KeyboardButton(text="⬅️ Назад в меню"))

# KB_CONTACT: Final = ReplyKeyboardMarkup(row_width=1, resize_keyboard=True)
# KB_CONTACT.add(KeyboardButton("Отправить контакт 📞", request_contact=True))