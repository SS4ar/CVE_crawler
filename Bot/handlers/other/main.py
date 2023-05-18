import requests

from Bot.config import API_URL
from Bot.keyboards import reply
from Bot.keyboards import inline

from aiogram import Dispatcher, Bot
from aiogram.types import Message, User


async def other_messages(msg: Message) -> None:
    bot: Bot = msg.bot
    user: User = msg.from_user

    await bot.send_message(chat_id=user.id,
                           text=f"🤔 Команда  <b>«{msg.text}»></b>  не распознана",
                           reply_markup=reply.KB_GOTO_MENU)


async def __start(msg: Message) -> None:
    bot: Bot = msg.bot
    user: User = msg.from_user

    reg_request_url = API_URL + "register"
    response = requests.post(url=reg_request_url,
                             json={"chat_id": f"{user.id}"},
                             headers={
                                 'Content-type': 'application/json',
                                 'Accept': 'application/json'
                             })
    print(response)

    await bot.send_message(chat_id=user.id,
                           text=f"Добро пожаловать! 👋\n\n"
                                f"Данный бот создан для специалистов, работающих в области кибербезопасности, "
                                f"которым необходимо всегда быть в курсе самых актуальных киберугроз, "
                                f"чтобы своевременно противостоять им.\n\n"
                                f"<b>Переходи в меню, чтобы произвести поиск уязвимостей по базе CVE.</b>",
                           reply_markup=reply.KB_GOTO_MENU)


def register_other_handlers(dp: Dispatcher) -> None:
    dp.register_message_handler(__start, commands=["start"])
    dp.register_message_handler(other_messages, content_types=['text'], state=None)