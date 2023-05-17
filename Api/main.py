from flask import Flask, request
from handlers import parser
import sqlite3
import requests
import datetime
import schedule
import threading
import time


app = Flask(__name__)
db = "users.db"


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
        print(data)
        return data
    else:
        print('Ошибка при получении новых CVE:', response.status_code)
        return []


def check_user_wishes():
    new_cves = get_new_cves()
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    for user in users:
        chat_id = user['chatid']
        wishes = user['wishes'].split(';')
        cvss = user['cvss']
        for cve in new_cves:
            response = parser.request_by_Id(cve)
            cvss_score = response['cvss3']['baseScore']
            url = 'https://api.telegram.org/bot6097752660:AAHEfco55h-eA_lBcKwN_oxomcSO-ga09LE/sendMessage?chat_id=' + chat_id + '''&text=🔔 Уведомление по подписке на уязвимости

            В базе CVE появилась новая уязвимость под номером''' + cve + '''

            Чтобы отключить подписку, перейдите в Меню -> Подписка на уведомления -> Отключить подписку'''
            if (wish in response for wish in wishes) and cvss > cvss_score:
                request.get(url)
            elif wishes == None or cvss == None:
                request.get(url)
    conn.close()

def run_scheduler():
    # Определяем задачу для выполнения каждые 6 часов
    schedule.every(6).hours.do(check_user_wishes)

    while True:
        schedule.run_pending()
        time.sleep(1)

def register_user(chat_id):
    conn = sqlite3.connect(db)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE chatid=?", (chat_id,))
    existing_user = cursor.fetchone()
    if not existing_user:
        cursor.execute("INSERT INTO users (chatid, wishes, cvss) VALUES (?, ?, ?)", (chat_id, None))
        conn.commit()
    conn.close()


def update_wishes(chat_id, new_wishes, new_cvss):
    conn = sqlite3.connect(db)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE chatid=?", (chat_id,))
    existing_user = cursor.fetchone()
    if existing_user:
        cursor.execute("UPDATE users SET wishes=?,cvss=? WHERE chatid=?", (new_wishes, new_cvss, chat_id,))
        conn.commit()
    conn.close()


@app.route('/api/cve/update_wishes', methods=['POST'])
def handle_update_wishes():
    data = request.get_json()
    chat_id = data['chat_id']
    new_wishes = data['new_wishes']

    update_wishes(chat_id, new_wishes)

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
    date_start =parser.convert_date(date_start)
    date_end = parser.convert_date(date_end)
    try:
        json_data = parser.request_by_date(date_start, date_end)
        return json_data #вернется список из цве вышедших в заданный период, к ним на фронте желательно прикрепить
        # гиперссылки на запрос по заданной цве
    except Exception:
        return "Ошибка при выполнении запроса"


def start_api():
    scheduler_thread = threading.Thread(target=run_scheduler)
    scheduler_thread.start()
    app.run(debug=True)
    get_new_cves()


if __name__ == '__main__':
    get_new_cves()
    start_api()
