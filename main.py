message = '28.12.1998'
date = []
if '.' in message:
    date = message.split('.')
if len(message) > 2 and int(date[0]) in range(1, 32) and int(date[1]) in range(1,13) and int(date[2]) in range(1900, 2024):
    print('a')