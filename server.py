import socket
import struct
import base64
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import rsa, padding #For confidentiality because of RSA and padding packages that are used for encrypting and adding data to a message to ensure security
from cryptography.hazmat.primitives import serialization, hashes #Serialization is for the communication while hashes are for integrity and non repudiation depending on how it is used
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding # Padding that is specifically made to work with RSA


run = True

# Non repudiation portion of the code
# Done by the sender as a guarantee on the message's source
def sign_message(private_key, message: bytes) -> bytes:
    return private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# Done by the receiver to check if the sender REALLY sent this one
def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# To generate the keys for the RSA. Public key and private key are generated here.
def gen_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Teehee -> 13256132475072. Serialize is turning a message into a sequence of bytes
def serialize_public(pub):
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# 13256132475072 -> Teehee. Deserialize is turning a sequence of bytes into a message
def deserialize_public(data):
    return serialization.load_pem_public_key(data)

# This is the 'container' for the message sent from another sender. Designed to receive exact n bytes of data.
def recv_exact(conn, n):
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while receiving")
        buf += chunk
    return buf

# Sends the length of the message YOU sent. I.E. if you sent "hey", its going "3-hey"
def send_with_length(conn, data: bytes):
    conn.sendall(struct.pack('>I', len(data)))
    conn.sendall(data)

# Receives the length from the other sender's send_with_length
def recv_with_length(conn):
    raw_len = recv_exact(conn, 4)
    (length,) = struct.unpack('>I', raw_len)
    return recv_exact(conn, length)

# Encrypts the message with RSA
def encrypt_message(pub, message: str) -> bytes:
    return pub.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# Decrypts the message and returns a decoded message
def decrypt_message(priv, ciphertext: bytes) -> str:
    plain = priv.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return plain.decode()

# Receiving message from Client
def receiveMsg(conn, private_key):
    global run
    try:
        while run:
            try:
                ciphertext = recv_with_length(conn)
                signature = recv_with_length(conn)
            except:
                run = False
                break

            if not verify_signature(client_public, ciphertext, signature):
                print("[WARNING] Invalid signature! Message dropped.")
                continue

            try:
                msg = decrypt_message(private_key, ciphertext)
            except:
                continue

            print(f"\nClient: {msg}")
            print("Server: ", end="", flush=True)

            if msg.strip() == "/quit":
                print("Closing connection")
                run = False
                break
    except:
        run = False

#Sending message to client
def sendMessage(conn, peer_public):
    global run
    try:
        while run:
            print("Server: ", end="", flush=True)
            msg = input()  

            ciphertext = encrypt_message(peer_public, msg)
            signature = sign_message(private_key, ciphertext)

            send_with_length(conn, ciphertext)
            send_with_length(conn, signature)

            if msg.strip() == '/quit':
                print("Closing connection")
                run = False
                break
    except:
        run = False

# run first in order to establish a connection
def listenConnection():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 8000))
    s.listen(1)
    conn, addr = s.accept()
    print('Server accepted client connection...')
    return conn, addr, s

# Initializing for run time
if __name__ == '__main__':
    private_key, public_key = gen_keys()
    conn, addr, s = listenConnection()

    server_pub_bytes = serialize_public(public_key)
    send_with_length(conn, server_pub_bytes)

    client_pub_bytes = recv_with_length(conn)
    client_public = deserialize_public(client_pub_bytes)

    rcv = Thread(target=receiveMsg, args=(conn, private_key))
    rcv.start()
    snd = Thread(target=sendMessage, args=(conn, client_public))
    snd.start()

    rcv.join()
    snd.join()
    conn.close()
    s.close()
