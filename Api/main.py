from flask import Flask
from handlers import parser

app = Flask(__name__)


@app.route('/')
def hello():
    return "555"


@app.route('/api/cve/<string:cve_numb>', methods=['GET'])
def handle_data(cve_numb):
    data = parser.request_by_Id(cve_numb)
    return data


def start_api():
    app.run(debug=True)


if __name__ == '__main__':
    start_api()
