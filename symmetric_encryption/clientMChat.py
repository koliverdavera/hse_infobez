import socket
import errno
import sys
from cryptography.fernet import Fernet

HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 1234
my_username = input("Username: ")

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((IP, PORT))
client_socket.setblocking(False)

username = my_username.encode('utf-8')
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
client_socket.send(username_header + username)


def save_key(key, client_name=my_username):
    with open(f'{client_name}.key', 'wb') as filekey:
        filekey.write(key)


def read_key(username):
    with open(f'{username}.key', 'rb') as filekey:
        content = filekey.read()
    return content


def decode_message(username, encrypted_message):
    key = read_key(username)
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message)
    decoded_message = decrypted_message.decode('utf-8')
    return decoded_message


while True:

    message = input(f'{my_username} > ')

    if message:

        key = Fernet.generate_key()
        save_key(key)
        fer = Fernet(key)

        message = message.encode('utf-8')
        message = fer.encrypt(message)

        message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
        client_socket.send(message_header + message)

    try:
        # Now we want to loop over received messages (there might be more than one) and print them
        while True:

            username_header = client_socket.recv(HEADER_LENGTH)

            if not len(username_header):
                print('Connection closed by the server')
                sys.exit()

            username_length = int(username_header.decode('utf-8').strip())
            username = client_socket.recv(username_length).decode('utf-8')

            message_header = client_socket.recv(HEADER_LENGTH)
            message_length = int(message_header.decode('utf-8').strip())
            message = client_socket.recv(message_length).decode('utf-8')

            message = decode_message(username, message)

            print(f'{username} > {message}')

    except IOError as e:
        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
            print('Reading error: {}'.format(str(e)))
            sys.exit()

        continue

    except Exception as e:
        print('Reading error: '.format(str(e)))
        sys.exit()
