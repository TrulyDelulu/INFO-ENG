import socket

run = True

def listenConnection():
    bind_ip = input("Enter IP Address of this server: ")
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((bind_ip, 9000))
    s.listen(1)
    conn, addr = s.accept()
    print('Attacker accepted connection from Sniffer...')
    return conn, addr, s

if __name__ == '__main__':
    print("run 'ipconfig' (windows) or 'ip a' (linux) for IP address of machine.\n\n")
    print("Im Attacker >:)\n\n")
        
    conn, addr, s = listenConnection()

    while run:
        try:
            data = conn.recv(4096)
            if not data:
                continue
            print(data.decode())

        except socket.error as msg:
            run = False
        except KeyboardInterrupt:
            run = False

    conn.close()