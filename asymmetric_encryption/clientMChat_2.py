import socket
import errno
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

HEADER_LENGTH = 100

IP = "127.0.0.1"
PORT = 1234
DELIMITER = b"\n\n\n\n"
KEY_SIZE = 2048

my_username = input("Username: ")

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((IP, PORT))
client_socket.setblocking(False)

username = my_username.encode('utf-8')
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
client_socket.send(username_header + username)

# {peer_username: [peer_public_key, exchanged_key]}
companions = dict()


def encrypt_message(message_text, my_public_key: rsa.RSAPublicKey, recipient_key: rsa.RSAPublicKey or None):
    key_bytes = my_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # message_content = key_bytes.decode() + DELIMITER + message_text
    if recipient_key:
        # key_encrypted = recipient_key.encrypt(
        #     key_bytes,
        #     padding.OAEP(
        #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #         algorithm=hashes.SHA256(),
        #         label=None
        #     )
        # )

        message_text_encrypted = recipient_key.encrypt(
            message_text.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        message_encrypted = key_bytes + DELIMITER + message_text_encrypted

    else:
        message_encrypted = key_bytes + DELIMITER + message_text.encode('utf-8')
    # message_content = key_bytes + b'\n\n\n\n' + message_encrypted
    message_header = f"{len(message_encrypted):<{HEADER_LENGTH}}".encode('utf-8')
    return message_header + message_encrypted


def send_and_encrypt_message(client_socket, message_text, my_public_key: rsa.RSAPublicKey, recipient_key: rsa.RSAPublicKey or None):
    encrypted_message = encrypt_message(message_text, my_public_key, recipient_key)
    client_socket.send(encrypted_message)


def read_message(client_socket, HEADER_LENGTH=HEADER_LENGTH):
    username_header = client_socket.recv(HEADER_LENGTH)

    if not len(username_header):
        print('Connection closed by the server')
        sys.exit()

    username_length = int(username_header.decode('utf-8').strip())
    username = client_socket.recv(username_length).decode('utf-8')

    message_header = client_socket.recv(HEADER_LENGTH)
    message_length = int(message_header.decode('utf-8').strip())
    # message = client_socket.recv(message_length).decode('utf-8')
    message = client_socket.recv(message_length)
    # n, e, message_text = message.split(';')

    return username, message


def parse_and_decode_message(username,
                             message_encrypted,
                             my_private_key: rsa.RSAPrivateKey):
    if len(message_encrypted.split(DELIMITER)) < 2:
        raise Exception('Received message with wrong format (no delimiter !)')
    key_components, encrypted_message = message_encrypted.split(DELIMITER)
    if username not in companions.keys():
        companions[username] = [
            serialization.load_pem_public_key(
                key_components,
                backend=default_backend()
            ),
            False
        ]
        return False, encrypted_message
    else:
        if companions[username][1]:
            print(f'\n\nCHECK KEY LEN {len(encrypted_message) == KEY_SIZE}')
            decrypted_message = my_private_key.decrypt(
                encrypted_message.ljust(KEY_SIZE, b' '),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return True, decrypted_message
        else:
            # собеседник еще не получил наш ключ, отправил несколько сообщений в незашифрованном виде
            # тогда его юзернейм и ключ уже будут у нас, но попытка расшифровать нашим приватным ключом упадет
            return True, encrypted_message
        # except Exception as e:
        #     print(f'\nReceived message from {username}, but you have no key to decrypt it', e)
        #     return False, encrypted_message


if __name__ == '__main__':

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((IP, PORT))
    client_socket.setblocking(False)

    username = my_username.encode('utf-8')
    username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(username_header + username)

    my_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend()
    )

    my_public_key = my_private_key.public_key()

    while True:

        if len(companions.keys()) > 0:
            print('Enter recipient username:')
            recipient = input()
            if recipient not in companions.keys():
                print('This recipient has not registered yet!')
                continue
            recipient_key = companions[recipient][0]
            companions[recipient][1] = True
        else:
            print('No one has registered yet, so your message will not be encrypted.')
            recipient_key = None
            recipient = None

        message = input(f'{my_username}, enter your message {"to " + recipient if recipient else "to everyone"} > \n > ')

        if message:
            send_and_encrypt_message(client_socket, message, my_public_key, recipient_key)

        try:
            # Now we want to loop over received messages (there might be more than one) and print them
            while True:
                username, message_encrypted = read_message(client_socket, HEADER_LENGTH)
                decryption_result, message_decrypted = parse_and_decode_message(username, message_encrypted, my_private_key)

                if decryption_result:
                    print(f'{username} sent a message to you > \n{message_decrypted}\n')
                # username_header = client_socket.recv(HEADER_LENGTH)
                #
                # if not len(username_header):
                #     print('Connection closed by the server')
                #     sys.exit()
                #
                # username_length = int(username_header.decode('utf-8').strip())
                # username = client_socket.recv(username_length).decode('utf-8')
                #
                # message_header = client_socket.recv(HEADER_LENGTH)
                # message_length = int(message_header.decode('utf-8').strip())
                # message = client_socket.recv(message_length).decode('utf-8')
                #
                # # message = decode_message(username, message)
                #

        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print('Reading error: {}'.format(str(e)))
                sys.exit()
            continue

        except Exception as e:
            print('Reading error: {}'.format(str(e)))
            sys.exit()
