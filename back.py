from flask import Flask, request
from parcer import  request_by_Id

app = Flask(__name__)


@app.route('/')
def hello():
    return "555"


@app.route('/api/cve/<string:cve_numb>', methods=['GET'])
def handle_data(cve_numb):
    data = request_by_Id(cve_numb)
    return data



if __name__ == '__main__':
    app.run()
