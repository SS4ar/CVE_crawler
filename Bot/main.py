from aiogram.utils import executor
from aiogram import Bot, Dispatcher
from aiogram.contrib.fsm_storage.memory import MemoryStorage

from Bot import handlers, filters, database, config


async def __on_start_up(dp: Dispatcher) -> None:
    filters.register_all_filters(dp)
    handlers.register_all_handlers(dp)
    # register_models()


def start_bot():
    bot = Bot(token=config.BOT_TOKEN, parse_mode='HTML')
    dp = Dispatcher(bot, storage=MemoryStorage())
    executor.start_polling(dp, skip_updates=True, on_startup=__on_start_up)


if __name__ == '__main__':
    start_bot()
