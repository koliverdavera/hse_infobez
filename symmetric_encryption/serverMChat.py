import socket
import select

HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 1234
# client_socket: {'user':
#                      {'header': user_header,
#                      'data': username},
#                 'message':
#                      {'header': message_header,
#                      'data':'message_data'}}
clients = {}


def receive_message(client_socket):
    try:
        message_header = client_socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False
        message_length = int(message_header.decode('utf-8').strip())
        print(message_length, message_header)
        return {'header': message_header, 'data': client_socket.recv(message_length)}
    except:
        return False


def send_message(notified_socket):
    user = clients[notified_socket]['user']
    message = clients[notified_socket]['message']
    for client_socket in clients.keys():
        if client_socket != notified_socket:
            client_socket.send(user['header'] + user['data'] + message['header'] + message['data'])
            print('SENT MESSAGE TO ', clients[client_socket]['user']['data'])
            print(user['header'] + user['data'] + message['header'] + message['data'])


def send_users_list():
    message_header = f"{str(-1):<{HEADER_LENGTH}}".encode('utf-8')
    users_str = b' '.join(list(map(lambda x: x['user']['data'], clients.values())))
    users_header = f"{len(users_str):<{HEADER_LENGTH}}".encode('utf-8')
    for client_socket in clients.keys():
        client_socket.send(message_header + users_header + users_str)


if __name__ == '__main__':
    # Create a socket
    # socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
    # socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # SO_ - socket option
    # SOL_ - socket option level
    # Sets REUSEADDR (as a socket option) to 1 on socket
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((IP, PORT))
    server_socket.listen()
    sockets_list = [server_socket]

    print(f'Listening for connections on {IP}:{PORT}...')

    while True:

        # Calls Unix select() system call or Windows select() WinSock call with three parameters:
        #   - rlist - sockets to be monitored for incoming data
        #   - wlist - sockets for data to be send to (checks if for example buffers are not full and socket is ready to send some data)
        #   - xlist - sockets to be monitored for exceptions (we want to monitor all sockets for errors, so we can use rlist)
        # Returns lists:
        #   - reading - sockets we received some data on (that way we don't have to check sockets manually)
        #   - writing - sockets ready for data to be sent through them
        #   - errors  - sockets with some exceptions
        # This is a blocking call, code execution will "wait" here and "get" notified in case any action should be taken
        read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)

        for notified_socket in read_sockets:
            if notified_socket == server_socket:
                # Accept new connection
                # That gives us new socket - client socket, connected to this given client only, it's unique for that client
                # The other returned object is ip/port set
                client_socket, client_address = server_socket.accept()
                user = receive_message(client_socket)
                if user is False:
                    continue
                sockets_list.append(client_socket)
                clients[client_socket] = {'user': user, 'message': {'header': None, 'data':None}}
                send_users_list()
                print('Accepted new connection from {}:{}, username: {}'.format(*client_address, user['data'].decode('utf-8')))

            else:
                message = receive_message(notified_socket)
                if message is False:
                    print('Closed connection from: {}'.format(clients[notified_socket]['user']['data']))
                    sockets_list.remove(notified_socket)
                    del clients[notified_socket]
                    continue
                clients[notified_socket]['message'] = message
                user = clients[notified_socket]['user']
                print(f'Received message from {user["data"].decode("utf-8")}: {message["data"]}')
                send_message(notified_socket)
        # It's not really necessary to have this, but will handle some socket exceptions just in case
        for notified_socket in exception_sockets:
            sockets_list.remove(notified_socket)
            del clients[notified_socket]
