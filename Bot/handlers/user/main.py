from Bot.keyboards import reply
from Bot.keyboards import inline

from aiogram import Dispatcher, Bot
from aiogram.types import Message, User

from Bot.utils.cve_finder import CVEFinder, CVE
from Bot.utils.translator import TextTranslation


async def __main_menu(msg: Message) -> None:
    bot: Bot = msg.bot
    user: User = msg.from_user

    await bot.send_message(chat_id=user.id,
                           text=f"<b>Вы находитесь в главном меню.</b>",
                           reply_markup=reply.KB_MAIN_MENU)


async def __vuln_finder_menu(msg: Message) -> None:
    bot: Bot = msg.bot
    user: User = msg.from_user

    await bot.send_photo(chat_id=user.id,
                         photo="https://i.imgur.com/C5VJagf.png",
                         caption=f"<b><u>Вы находитесь в меню поиска уязвимостей.</u></b>\n\n"
                                 f"Для того, чтобы произвести поиск уязвимости по номеру CVE "
                                 f"произведите запрос в следующей форме:\n"
                                 f"<code class=\"language-python\"><b>CVE-****-****</b></code>\n"
                                 f"Где <code class=\"language-python\">*</code> - любое число",
                         reply_markup=reply.VULN_FINDER_MENU)


async def __find_cve_by_id(msg: Message) -> None:
    bot: Bot = msg.bot
    user: User = msg.from_user

    found_cve: CVE = CVEFinder().get_by_id(msg.text)

    response_text = f"<b>✅ Уязвимость найдена!</b>\n\n" \
               f"<b><u>{found_cve.id}</u></b>\n" \
               f"🕐 Дата обнаружения: {found_cve.pub_date_time}\n\n" \
               f"🇺🇸 Описание на EN: {found_cve.name}\n\n" \
               f"🇷🇺 Описание на RU: {TextTranslation().translate(text=found_cve.name)}"

    await bot.send_message(chat_id=user.id,
                           text=response_text,
                           reply_markup=inline.KB_CVE_PARAMS)


async def __vuln_subscription(msg: Message) -> None:
    bot: Bot = msg.bot
    user: User = msg.from_user

    await bot.send_message(chat_id=user.id,
                           text=f"Функция ещё не реализована.",
                           reply_markup=reply.KB_BACK_TO_MENU)


async def __profile(msg: Message) -> None:
    bot: Bot = msg.bot
    user: User = msg.from_user

    await bot.send_message(chat_id=user.id,
                           text=f"<b>Никнейм:</b> {user.username}\n"
                                f"<b>ID Пользователя:</b> {user.id}",
                           reply_markup=reply.KB_BACK_TO_MENU)


def register_user_handlers(dp: Dispatcher) -> None:
    dp.register_message_handler(__find_cve_by_id, regexp=r"CVE-\d{4}-\d{4,5}$|CVE-\d{4}-\d{7}$")
    dp.register_message_handler(__main_menu, lambda message: message.text == "⬅️ Назад в меню")
    dp.register_message_handler(__main_menu, lambda message: message.text == "ℹ️ Показать меню")
    dp.register_message_handler(__vuln_finder_menu, lambda message: message.text == "🔍 Поиск уязвимостей")
    dp.register_message_handler(__vuln_subscription, lambda message: message.text == "🔔 Подписка на уведомления")
    dp.register_message_handler(__profile, lambda message: message.text == "👤 Профиль")
