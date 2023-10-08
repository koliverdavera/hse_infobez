import socket
import select
import rsa

HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 1234

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((IP, PORT))
server_socket.listen()

sockets_list = [server_socket]
clients = dict()
DELIMITER = '/n/n'

print(f'Listening for connections on {IP}:{PORT}...')

def parse_key(client_socket) -> dict:
    keys_header = client_socket.recv(HEADER_LENGTH)
    if not len(keys_header):
        return False
    keys_length = int(keys_header.decode('utf-8').strip())
    key_components = client_socket.recv(keys_length).decode('utf-8')
    n, e = map(int, key_components.split(';'))
    key = rsa.PublicKey(n=n, e=e)
    return {'header': keys_header, 'data': key}


def receive_message(client_socket):
    try:
        message_header = client_socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False
        message_length = int(message_header.decode('utf-8').strip())
        if message_length == -1:
            return parse_key(client_socket)
        else:
            return {'header': message_header, 'data': client_socket.recv(message_length)}
    except Exception as e:
        return False


def send_keys_to_everyone(clients):
    all_keys = "".encode('utf-8')

    for client_values in clients.values():
        username = client_values['username'].decode('utf-8')
        key = client_values['key']
        if key is None:
            continue
        key = f'{key.n};{key.e}'
        # записываем в строку все публичные ключи в формате "длина имени + имя + длина ключа + ключ"
        all_keys += (
                str(len(username)) + DELIMITER + username + DELIMITER +
                str(len(key)) + DELIMITER + key + DELIMITER
        ).encode('utf-8')

    public_header = f"{-1:<{HEADER_LENGTH}}".encode('utf-8')
    len_users_header = f"{len(all_keys):<{HEADER_LENGTH}}".encode('utf-8')

    for client_socket in clients:
        client_socket.send(public_header + len_users_header + all_keys)


while True:
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)
    for notified_socket in read_sockets:
        if notified_socket == server_socket:
            client_socket, client_address = server_socket.accept()
            user_message = receive_message(client_socket)
            if user_message is False:
                continue
            sockets_list.append(client_socket)
            print('Accepted new connection from {}:{}, username: {}'.format(*client_address,
                                                                            user_message['data']))
            # мы точно знаем, что первое сообщение от юзера содержит только юзернейм
            clients[client_socket] = {
                'username_header': user_message['header'],
                'username': user_message['data'],
                'key': None
            }
        else:
            user_message = receive_message(notified_socket)
            if user_message is False:
                print('Closed connection from: {}'.format(clients[notified_socket]['username']))
                sockets_list.remove(notified_socket)
                del clients[notified_socket]
                continue
            username = clients[notified_socket]['username']
            if clients[notified_socket]['key'] is None:
                # мы точно знаем, что второе сообщение от нового юзера будет содержать ключ
                clients[notified_socket]['key'] = user_message['data']
                send_keys_to_everyone(clients)
                continue
            else:
                print(f'Received message from {username}: {user_message["data"]}')
                for client_socket in clients:
                    if client_socket != notified_socket:
                        sender = list(filter(lambda x: x['username'] == username, clients.values()))[0]
                        message = (
                            sender['username_header'] + sender['username'] +
                            user_message['header'] + user_message['data']
                        )
                        client_socket.send(message)

    for notified_socket in exception_sockets:
        sockets_list.remove(notified_socket)
        del clients[notified_socket]
