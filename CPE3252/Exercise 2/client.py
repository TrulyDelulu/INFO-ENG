import socket
from threading import Thread

run = True

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

if __name__ == '__main__':
    bind_ip = input("Enter IP Address of this device: ")
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((bind_ip, 8000))
    rcv = Thread(target=receiveMsg, args=(s,))
    snd = Thread(target=sendMessage, args=(s,))
    rcv.start()
    snd.start()

    rcv.join()
    snd.join()
