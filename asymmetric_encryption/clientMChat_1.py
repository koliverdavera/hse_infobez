import socket
import errno
import sys
import rsa


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

# {username: his_public_key}
companions = dict()


def send_encrypted_message(client_socket, message, sender_key: rsa.PublicKey or None):
    message = message.encode('utf-8')
    if sender_key:
        message = rsa.encrypt(message, sender_key)
    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(message_header + message)


# def send_public_key_to_server(client_socket, public_key: rsa.PublicKey):
#     message = (str(public_key.n) + ';' + str(public_key.e)).encode('utf-8')
#     message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
#     client_socket.send(message_header + message)

def save_public_key(public_key: rsa.PublicKey, path='public_keys'):
    with open(f'{path}/{my_username}.key', 'wb') as filekey:
        filekey.write(f'{public_key.n};{public_key.e}'.encode('utf-8'))


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

    return username, message


def parse_new_key(username, encrypted_key):
    n, e = map(int, encrypted_key.split(';'))
    decrypted_key = rsa.PublicKey(n=n, e=e)
    companions[username] = decrypted_key
    return decrypted_key


def decode_message(message, private_key: rsa.PrivateKey):
    decoded_message = rsa.decrypt(message, private_key)
    return decoded_message


if __name__ == '__main__':

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((IP, PORT))
    client_socket.setblocking(False)

    username = my_username.encode('utf-8')
    username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(username_header + username)

    my_public_key, my_private_key = rsa.newkeys(512)
    save_public_key(my_public_key)

    current_key = None

    while True:

        message = input(f'{my_username} > ')

        if message:
            send_encrypted_message(client_socket, message, current_key)

        try:
            while True:
                username, message = read_message(client_socket)
                if username not in companions:
                    parse_new_key(username, message)
                message = decode_message(message, my_private_key)
                print(f'{username} > {message}')

        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print('Reading error: {}'.format(str(e)))
                sys.exit()
            continue

        except Exception as e:
            print('Reading error: {}'.format(str(e)))
            sys.exit()
