import os
import select
import socket
import sys

from cryptography.fernet import Fernet

HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 1234
KEY_PATH = 'user_keys'
clients = dict()


def read_key_from_file(filename):
    with open(f"{KEY_PATH}/{filename}", 'rb') as filekey:
        content = filekey.read()
        key = Fernet(content)
        return key


def save_new_key(my_username, recipient_name):
    key = Fernet.generate_key()
    with open(f'{KEY_PATH}/{my_username}_{recipient_name}.key', 'wb') as filekey:
        filekey.write(key)
    return Fernet(key)


def get_key(my_username, recipient_name, create_if_not_exists=False):
    names = [f'{my_username}_{recipient_name}.key',
             f'{recipient_name}_{my_username}.key']
    # print(names)
    for name in names:
        if name in os.listdir(KEY_PATH):
            return read_key_from_file(name)
    if create_if_not_exists and recipient_name:
        return save_new_key(my_username, recipient_name)
    else:
        return


def choose_recipient():
    if len(clients) <= 1:
        print('No one has registered yet')
        return
    print('Choose recipient:')
    print(*filter(lambda user: user != my_username, clients))
    recipient = input('Enter recipient name: ')
    if recipient not in clients:
        print('This user has not registered yet!')
        return choose_recipient()
    return recipient


def send_message(client_socket, recipient_name):
    key = get_key(my_username, recipient_name, create_if_not_exists=True)
    if recipient_name is None:
        print("You are the first user, so your message won't be encrypted")
    else:
        print(f'Write your message to {recipient_name}')
    message_text = input(f'{my_username} > ')
    if message_text and recipient_name:
        # fer = Fernet(key)
        message_encoded = message_text.encode('utf-8')
        message_encrypted = key.encrypt(message_encoded)
        message_header = f"{len(message_encrypted):<{HEADER_LENGTH}}".encode('utf-8')
        client_socket.send(message_header + message_encrypted)



def decrypt_message(sender_name, encrypted_message):
    key = get_key(my_username, sender_name, create_if_not_exists=False)
    if not key:
        return
    # fernet = Fernet(key)
    decrypted_message = key.decrypt(encrypted_message)
    decoded_message = decrypted_message.decode('utf-8')
    return decoded_message


def parse_users(client_socket):
    users_header = int(client_socket.recv(HEADER_LENGTH).strip())
    users_list = (client_socket.recv(users_header).decode('utf-8').split())
    for user in users_list:
        clients[user] = f"{len(user):<{HEADER_LENGTH}}"


def read_message(client_socket):
    username_header = client_socket.recv(HEADER_LENGTH)
    if not len(username_header):
        print('Connection closed by the server')
        sys.exit()
    sender_name_length = int(username_header.decode('utf-8').strip())
    if sender_name_length == -1:
        return parse_users(client_socket)
    sender_name = client_socket.recv(sender_name_length).decode('utf-8')
    message_header = client_socket.recv(HEADER_LENGTH)
    message_length = int(message_header.decode('utf-8').strip())
    message_encrypted = client_socket.recv(message_length)
    message_decrypted = decrypt_message(sender_name, message_encrypted)
    if message_decrypted:
        print(f'{sender_name} > {message_decrypted}')


def init_user(client_socket: socket):
    my_username = input("Username: ")
    username = my_username.encode('utf-8')
    username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(username_header + username)
    return my_username


def init_socket():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((IP, PORT))
    client_socket.setblocking(False)
    return client_socket


def init_registered_users(client_socket):
    ready, _, _ = select.select([client_socket], [], [], 2)
    if ready:
        read_message(ready[0])
    else:
        return init_registered_users(client_socket)


def init_keys():
    for file in os.listdir(KEY_PATH):
        file_path = os.path.join(KEY_PATH, file)
        os.remove(file_path)


if __name__ == '__main__':
    while True:
        client_socket = init_socket()
        my_username = init_user(client_socket)
        init_registered_users(client_socket)
        init_keys()

        while True:
            recipient_name = choose_recipient()
            send_message(client_socket, recipient_name)

            ready, _, _ = select.select([client_socket], [], [], 0.1)
            if ready:
                read_message(ready[0])
            else:
                continue

        # message = input(f'{my_username} > ')
        #
        # if message:
        #     key = Fernet.generate_key()
        #     save_key(key)
        #     fer = Fernet(key)
        #
        #     message = message.encode('utf-8')
        #     message = fer.encrypt(message)
        #
        #     message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
        #     client_socket.send(message_header + message)
        #
        # try:
        #     while True:
        #         username_header = client_socket.recv(HEADER_LENGTH)
        #         if not len(username_header):
        #             print('Connection closed by the server')
        #             sys.exit()
        #
        #         username_length = int(username_header.decode('utf-8').strip())
        #         username = client_socket.recv(username_length).decode('utf-8')
        #
        #         message_header = client_socket.recv(HEADER_LENGTH)
        #         message_length = int(message_header.decode('utf-8').strip())
        #         message = client_socket.recv(message_length).decode('utf-8')
        #
        #         message = decrypt_message(username, message)
        #
        #         print(f'{username} > {message}')
        #
        # except IOError as e:
        #     if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
        #         print('Reading error: {}'.format(str(e)))
        #         sys.exit()
        #     continue
        #
        # except Exception as e:
        #     print('Reading error: '.format(str(e)))
        #     sys.exit()
