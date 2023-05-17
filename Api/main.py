from flask import Flask, request
from Api.handlers import parser
import psycopg2
import requests
import datetime
import schedule
import threading
import time
import telebot

app = Flask(__name__)


def get_new_cves():
    current_date = datetime.date.today()
    current_datetime = datetime.datetime.now().isoformat(timespec='seconds')
    mod_start_date = current_date - datetime.timedelta(days=1)
    params = {
        'pubStartDate': mod_start_date.strftime('%Y-%m-%dT%H:%M:%S.%f'),
        'pubEndDate': current_datetime
    }
    response = requests.get(parser.base_vuln_api_url, params=params)
    if response.status_code == 200:
        cve_data = response.json()
        data = parser.parse_ids_from_res(cve_data)
        return data
    else:
        print('Ошибка при получении новых CVE:', response.status_code)
        return []


def check_user_wishes():
    bot = telebot.TeleBot(token='6097752660:AAHEfco55h-eA_lBcKwN_oxomcSO-ga09LE')
    new_cves = get_new_cves()
    conn = psycopg2.connect(database="postgres", user="postgres", password="1488", host="localhost", port="5432")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    for user in users:
        chat_id = user[1]
        wishes = user[2]
        if wishes != None:
            wishes = user[2].split(';')
        cvss = user[3]
        for cve in new_cves:
            response = parser.request_by_Id(cve)
            cvss_score = 0
            if 'cvss3' in response[0] and response[0]['cvss3'] != None:
                cvss_score = response[0]['cvss3']['baseScore']
            elif 'cvss2' in response[0] and response[0]['cvss2'] != None:
                cvss_score = response[0]['cvss2']
            else:
                cvss_score = 0
            print(cvss_score)
            text = '''🔔<u><b>Уведомление по подписке на уязвимости</b></u>

В базе CVE появилась новая уязвимость под номером<b> ''' + cve + '''</b>

Чтобы отключить подписку, перейдите в Меню -> Подписка на уведомления -> Отключить подписку'''
            if wishes != None and cvss != None:
                if (wish in response for wish in wishes) and cvss > cvss_score:
                    try:
                        bot.send_message(chat_id, text, parse_mode='HTML')
                    except Exception:
                        continue
            elif wishes[0] == 'ALL' and cvss == 10:
                try:
                    bot.send_message(chat_id, text, parse_mode='HTML')
                except Exception:
                    continue
            time.sleep(15)
    conn.close()


def run_scheduler():
    schedule.every(6).hours.do(check_user_wishes)

    while True:
        schedule.run_pending()
        time.sleep(1)


def register_user(chat_id):
    conn = psycopg2.connect(database="postgres", user="postgres", password="1488", host="localhost", port="5432")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE chatid = %s", (chat_id,))
    existing_user = cursor.fetchone()
    if not existing_user:
        cursor.execute("INSERT INTO users (chatid, wishes, cvss) VALUES (%s, %s, %s)", (chat_id, None, None))
        conn.commit()
    conn.close()


def update_wishes(chat_id, new_wishes, new_cvss):
    conn = psycopg2.connect(database="postgres", user="postgres", password="1488", host="localhost", port="5432")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE chatid = %s", (chat_id,))
    existing_user = cursor.fetchone()
    if existing_user:
        cursor.execute("UPDATE users SET wishes = %s, cvss = %s WHERE chatid = %s", (new_wishes, new_cvss, chat_id,))
        conn.commit()
    conn.close()


@app.route('/api/cve/update_wishes', methods=['PUT'])
def handle_update_wishes():
    data = request.get_json()
    chat_id = data['chat_id']
    new_wishes = data['wishes']
    new_cvss = data['cvss']
    update_wishes(chat_id, new_wishes, new_cvss)

    return 'Wishes updated successfully'


@app.route('/api/cve/register', methods=['POST'])
def handle_registration():
    data = request.get_json()
    chat_id = data['chat_id']
    wishes = data['wishes']
    register_user(chat_id, wishes)
    return 'Registration successful'


@app.route('/')
def hello():
    return "/"


@app.route('/api/cve/<string:cve_numb>', methods=['GET'])
def handle_data(cve_numb):
    data = parser.request_by_Id(cve_numb)
    return data


@app.route('/api/cve/sortbydate/<string:date_start>/<string:date_end>')
def handle_data1(date_start, date_end):
    date_start = parser.convert_date(date_start)
    date_end = parser.convert_date(date_end)
    try:
        json_data = parser.request_by_date(date_start, date_end)
        return json_data  # вернется список из цве вышедших в заданный период, к ним на фронте желательно прикрепить
        # гиперссылки на запрос по заданной цве
    except Exception:
        return "Ошибка при выполнении запроса"


def start_api():
    scheduler_thread = threading.Thread(target=run_scheduler)
    scheduler_thread.start()
    app.run(debug=True)


if __name__ == '__main__':
    start_api()
