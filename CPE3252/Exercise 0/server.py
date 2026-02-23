import socket
from threading import Thread

run = True


def receiveMsg(conn):
    global run
    while run:
        try:
            data = conn.recv(1024)
            if not data:
                continue
            print('\nMessage Received: {}'.format(data.decode()))

        except socket.error as msg:
            run = False
        except KeyboardInterrupt:
            run = False


def sendMessage(conn):
    global run

    while run:
        try:
            msg = input("Type Message: ")
            conn.sendall(msg.encode())
        except socket.error as err:
            run = False
        except KeyboardInterrupt:
            run = False


def listenConnection():
    bind_ip = input("Enter IP Address of this device: ")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((bind_ip, 8000))
    print('Listening...')
    s.listen(1)
    conn, addr = s.accept()
    print('Server accepted client connection...')
    return conn, addr, s

if __name__ == '__main__':
    conn, addr, s = listenConnection()
    rcv = Thread(target=receiveMsg, args=(conn, ))
    rcv.start()
    snd = Thread(target=sendMessage, args=(conn,))
    snd.start()
