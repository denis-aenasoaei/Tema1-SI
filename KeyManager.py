from Crypto.Cipher import AES
import socket
import os
import Padding

CRYPT_KEY = os.urandom(16)
KEY_FOR_KEYS = "A" * 16


counter = os.urandom(16)

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65433        # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while 1:
        CRYPT_KEY = os.urandom(16)
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            encryptor = AES.new(CRYPT_KEY, AES.MODE_CBC, bytearray("A" * 16, "UTF-8"))
            ENC_KEY = encryptor.encrypt(CRYPT_KEY)
            print(ENC_KEY)
            conn.sendall(ENC_KEY)
