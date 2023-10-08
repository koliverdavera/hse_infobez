import socket
import select
import errno
import sys
import rsa

HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 1234
KEY_SIZE = 1024
DELIMITER = '/n/n'
users = dict()


def send_message(client_socket, message_text, recipient):
    if recipient:
        return send_encrypted_message(client_socket, message_text, recipient)
    message_text = message_text.encode('utf-8')
    message_header = f"{len(message_text):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(message_header + message_text)


def send_encrypted_message(client_socket, message_text: str, recipient: str):
    message_bytes = message_text.encode('utf-8')
    key = users[recipient]['key']
    message_encrypted = rsa.encrypt(message_bytes, key)
    message_header = f"{len(message_encrypted):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(message_header + message_encrypted)


def parse_keys(client_socket):
    keys_header = client_socket.recv(HEADER_LENGTH).decode('utf-8')
    keys_length = int(keys_header.strip())
    keys = client_socket.recv(keys_length).decode('utf-8').split(DELIMITER)
    for i in range(0, len(keys), 4):
        if len(keys[i]) == 0:
            continue
        username_header = keys[i]
        username = keys[i + 1]
        key_header = keys[i + 2]
        n, e = map(int, keys[i + 3].split(';'))
        user_key = rsa.PublicKey(n=n, e=e)
        users[username] = {
            'username_header': username_header,
            'key_header': key_header,
            'key_str': keys[i + 3],
            'key': user_key
        }


def try_decode(message_encrypted, my_private_key: rsa.PrivateKey):
    try:
        return rsa.decrypt(message_encrypted, my_private_key).decode('utf-8')
    except rsa.DecryptionError as e:
        # print('message encrypted:', message_encrypted)
        # print(e)
        pass


def read_message(client_socket, HEADER_LENGTH=HEADER_LENGTH):
    username_header = client_socket.recv(HEADER_LENGTH)
    if not len(username_header):
        print('Connection closed by the server')
        sys.exit()
    username_length = int(username_header.decode('utf-8').strip())
    if username_length == -1:
        return parse_keys(client_socket)
    username = client_socket.recv(username_length).decode('utf-8')
    message_header = client_socket.recv(HEADER_LENGTH)
    message_length = int(message_header.decode('utf-8').strip())
    message_encrypted = client_socket.recv(message_length)
    message_decrypted = try_decode(message_encrypted, my_private_key)
    if message_decrypted:
        print(f'{username} > {message_decrypted}')


def choose_recipient():
    if len(users.keys()) < 2:
        print('No one has registered yet')
        return
    print('Choose recipient:')
    print(*filter(lambda user: user != my_username, users.keys()))
    recipient = input('Enter recipient name: ')
    if recipient not in users.keys() or recipient == my_username:
        print('You can not write messages to this user!')
        return choose_recipient()
    return recipient


def get_keys(client_socket):
    ready, _, _ = select.select([client_socket], [], [], 2)
    if ready:
        read_message(ready[0])
    else:
        return get_keys(client_socket)


def init_socket():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((IP, PORT))
    client_socket.setblocking(False)
    return client_socket


def init_user(client_socket: socket):
    my_username = input("Username: ")
    username = my_username.encode('utf-8')
    username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(username_header + username)
    return my_username


def init_keys(client_socket: socket):
    my_public_key, my_private_key = rsa.newkeys(512)
    key = f'{str(my_public_key.n)};{str(my_public_key.e)}'.encode('utf-8')
    public_header = f"{-1:<{HEADER_LENGTH}}".encode('utf-8')
    key_header = f"{len(key):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(public_header + key_header + key)
    get_keys(client_socket)
    return my_public_key, my_private_key


if __name__ == '__main__':

    client_socket = init_socket()
    my_username = init_user(client_socket)
    my_public_key, my_private_key = init_keys(client_socket)

    while True:
        recipient = choose_recipient()
        if recipient is None:
            print("You are the first user, so your message won't be encrypted")
        else:
            print(f'Write your message to {recipient}')
        message_text = input(f'{my_username} > ')

        if message_text:
            send_message(client_socket, message_text, recipient)

        ready, _, _ = select.select([client_socket], [], [], 0.1)
        if ready:
            read_message(ready[0])
        else:
            continue
        # try:
        #     while True:
        #         read_message(client_socket)
        #
        # except IOError as e:
        #     if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
        #         print('Reading error: {}'.format(str(e)))
        #         sys.exit()
        #     continue
