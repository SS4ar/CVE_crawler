from aiogram import Dispatcher

from Bot.handlers.admin import register_admin_handlers
from Bot.handlers.user import register_user_handlers
from Bot.handlers.other import register_other_handlers


def register_all_handlers(dp: Dispatcher) -> None:
    handlers = (
        register_user_handlers,
        # register_admin_handlers,
        register_other_handlers,
    )
    for handler in handlers:
        handler(dp)