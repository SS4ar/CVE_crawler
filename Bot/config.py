from dotenv import load_dotenv
import os

load_dotenv()

# Bot
SKIP_UPDATES = False
BOT_TOKEN = os.getenv('BOT_TOKEN')
LOGFILE = 'logs.txt'
OWNER_ID = 612666168

# Api
API_URL = 'http://192.168.1.180:5000/api/cve/'

print(BOT_TOKEN)