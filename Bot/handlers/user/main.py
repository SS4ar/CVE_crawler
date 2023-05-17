from Bot.keyboards import reply
from Bot.keyboards import inline

from aiogram import Dispatcher, Bot
from aiogram.types import Message, User, CallbackQuery

from Bot.utils.cve_finder import CVEFinder, CVE, CVEMessageFormatter
from Bot.utils.translator import TextTranslation

from Bot.keyboards.inline import CVECallbackActionsStatus


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

    loading_msg: Message = await bot.send_message(chat_id=user.id, text="⏳ Ищу информацию об уязвимости...")

    try:
        found_cve: CVE = CVEFinder().get_by_id(msg.text)
    except FileNotFoundError as ex:
        await bot.edit_message_text(chat_id=user.id,
                                    message_id=loading_msg.message_id,
                                    text="⚠️  Уязвимость не найдена!")
        return

    cve_message_formatter: CVEMessageFormatter = CVEMessageFormatter(cve=found_cve)

    response_text = cve_message_formatter.get_base_message()

    await bot.edit_message_text(chat_id=user.id,
                                message_id=loading_msg.message_id,
                                text=response_text,
                                reply_markup=inline.get_cve_keyboard(found_cve))


async def __show_actions(query: CallbackQuery, callback_data: dict) -> None:
    bot: Bot = query.bot
    user: User = query.from_user
    old_message = query.message

    found_cve: CVE = CVEFinder().get_by_id(callback_data['cve'])
    cve_message_formatter: CVEMessageFormatter = CVEMessageFormatter(cve=found_cve)

    message_text = cve_message_formatter.get_base_message()

    message_text += cve_message_formatter.get_recommended_actions()

    await bot.edit_message_text(chat_id=user.id,
                                message_id=old_message.message_id,
                                text=message_text,
                                reply_markup=inline.get_cve_keyboard(found_cve,
                                                                     callback_actions_status=CVECallbackActionsStatus(
                                                                         recommended_actions=True)))


async def __show_severity2x(query: CallbackQuery, callback_data: dict) -> None:
    bot: Bot = query.bot
    user: User = query.from_user
    old_message = query.message

    found_cve: CVE = CVEFinder().get_by_id(callback_data['cve'])
    cve_message_formatter: CVEMessageFormatter = CVEMessageFormatter(cve=found_cve)

    message_text = cve_message_formatter.get_base_message()

    message_text += CVEMessageFormatter(cve=found_cve).get_severity2x()

    await bot.edit_message_text(chat_id=user.id,
                                message_id=old_message.message_id,
                                text=message_text,
                                reply_markup=inline.get_cve_keyboard(found_cve,
                                                                     callback_actions_status=CVECallbackActionsStatus(
                                                                         severity_2x=True)))


async def __show_severity3x(query: CallbackQuery, callback_data: dict) -> None:
    bot: Bot = query.bot
    user: User = query.from_user
    old_message = query.message

    found_cve: CVE = CVEFinder().get_by_id(callback_data['cve'])
    cve_message_formatter: CVEMessageFormatter = CVEMessageFormatter(cve=found_cve)

    message_text = cve_message_formatter.get_base_message()

    message_text += CVEMessageFormatter(cve=found_cve).get_severity3x()

    await bot.edit_message_text(chat_id=user.id,
                                message_id=old_message.message_id,
                                text=message_text,
                                reply_markup=inline.get_cve_keyboard(found_cve,
                                                                     callback_actions_status=CVECallbackActionsStatus(
                                                                         severity_3x=True)))


async def __show_epss_rating(query: CallbackQuery, callback_data: dict) -> None:
    bot: Bot = query.bot
    user: User = query.from_user
    old_message = query.message

    found_cve: CVE = CVEFinder().get_by_id(callback_data['cve'])
    cve_message_formatter: CVEMessageFormatter = CVEMessageFormatter(cve=found_cve)

    message_text = cve_message_formatter.get_base_message()

    message_text += CVEMessageFormatter(cve=found_cve).get_epss_rating()

    await bot.edit_message_text(chat_id=user.id,
                                message_id=old_message.message_id,
                                text=message_text,
                                reply_markup=inline.get_cve_keyboard(found_cve,
                                                                     callback_actions_status=CVECallbackActionsStatus(
                                                                         epss_rating=True)))

async def __show_useful_urls(query: CallbackQuery, callback_data: dict) -> None:
    bot: Bot = query.bot
    user: User = query.from_user
    old_message = query.message

    found_cve: CVE = CVEFinder().get_by_id(callback_data['cve'])
    cve_message_formatter: CVEMessageFormatter = CVEMessageFormatter(cve=found_cve)

    message_text = cve_message_formatter.get_base_message()

    message_text += CVEMessageFormatter(cve=found_cve).get_useful_urls()

    await bot.edit_message_text(chat_id=user.id,
                                message_id=old_message.message_id,
                                text=message_text,
                                reply_markup=inline.get_cve_keyboard(found_cve,
                                                                     callback_actions_status=CVECallbackActionsStatus(
                                                                         useful_urls=True)))


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

    dp.register_callback_query_handler(__show_actions, inline.cve_callbacks.filter(action="cve_show_actions"))
    dp.register_callback_query_handler(__show_severity2x, inline.cve_callbacks.filter(action="cve_show_severity2x"))
    dp.register_callback_query_handler(__show_severity3x, inline.cve_callbacks.filter(action="cve_show_severity3x"))
    dp.register_callback_query_handler(__show_epss_rating, inline.cve_callbacks.filter(action="cve_show_epss_rating"))
    dp.register_callback_query_handler(__show_useful_urls, inline.cve_callbacks.filter(action="cve_show_useful_urls"))
