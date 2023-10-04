import socket
import select
import errno
import sys

HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 1234


def send_message(client_socket, message_text):
    message_text = message_text.encode('utf-8')
    message_header = f"{len(message_text):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(message_header + message_text)


def read_message(client_socket, HEADER_LENGTH=HEADER_LENGTH):
    username_header = client_socket.recv(HEADER_LENGTH)
    if not len(username_header):
        print('Connection closed by the server')
        sys.exit()
    username_length = int(username_header.decode('utf-8').strip())
    username = client_socket.recv(username_length).decode('utf-8')

    message_header = client_socket.recv(HEADER_LENGTH)
    message_length = int(message_header.decode('utf-8').strip())
    message = client_socket.recv(message_length).decode('utf-8')
    print(f'{username} > {message}')


if __name__ == '__main__':

    my_username = input("Username: ")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect((IP, PORT))
    client_socket.setblocking(False)

    username = my_username.encode('utf-8')
    username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')

    my_public_key =

    client_socket.send(username_header + username)

    while True:
        message = input(f'{my_username} > ')

        if message:
            send_message(client_socket, message)
        try:
            while True:
                read_message(client_socket)

        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print('Reading error: {}'.format(str(e)))
                sys.exit()
            continue

        except Exception as e:
            # Any other exception - something happened, exit
            print('Reading error: '.format(str(e)))
            sys.exit()
