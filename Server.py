import socket
from Crypto.Cipher import AES
import codecs

IV = bytearray("A" * 16, "UTF-8")
KEY_FOR_KEYS = bytearray("A" * 16, "UTF-8")

def pad_data(data):
    if len(data) % 16 == 0:
        return data
    databytes = bytearray(data, "UTF-8")
    padding_required = 16 - (len(databytes) % 16)
    databytes.extend(b'\x00' * padding_required)
    return bytes(databytes)

def unpad_data(data):
    if not data:
        return data
    pos = data.find(b'\x00')
    if pos != -1:
        data = data[:pos]
    return data

def xor_for_char(input_bytes, key_input):
    index = 0
    output_bytes = b''
    for byte in input_bytes:
        output_bytes += bytes([byte ^ key_input[index]])
        index += 1
    return output_bytes

def encrypt_CBC(plainText, key):
    plainText = pad_data(plainText)
    nb_blocks = (int)(len(plainText) / 16)
    iv = IV
    cypherText = bytearray(0)
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, nb_blocks):
            enc2 = xor_for_char(plainText[i * 16:(i + 1) * 16], iv)
            iv = cipher.encrypt(enc2)
            cypherText += iv
    return cypherText

def decrypt_CBC(cypherText, key):
    nb_blocks = (int) (len(cypherText)/16)
    byteText = bytearray()
    iv = IV
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, nb_blocks):
        enc2 = cipher.decrypt(cypherText[i*16:(i+1) * 16])
        byteText += xor_for_char(enc2, iv)
        iv = cypherText[i*16:(i+1) * 16]
    return unpad_data(byteText)

def encrypt_OFB(plainText, key):
    plainText = pad_data(plainText)
    nb_blocks = (int)(len(plainText) / 16)
    iv = IV
    cypherText = bytearray(0)
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(nb_blocks):
        iv = cipher.encrypt(iv)
        cypherText += xor_for_char(plainText[i * 16:(i + 1) * 16], iv)

    return cypherText


def decrypt_OFB(cypherText, key):
    nb_blocks = (int) (len(cypherText)/16)
    byteText = bytearray()
    iv = IV
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(nb_blocks):
        iv = cipher.encrypt(iv)
        byteText += xor_for_char(iv, cypherText[i*16:(i+1) * 16])
    return unpad_data(byteText)


#print(decrypt_CBC(encrypt_CBC("weasrdtfgyhfgtdrfsedawefrgt", "H" * 16), "H"*16))
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65421        # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while 1:
        conn, addr = s.accept()
        with conn:
            enc_mode = conn.recv(3).decode()
            cryptedKey = conn.recv(16)
            enc_key = decrypt_CBC(cryptedKey, KEY_FOR_KEYS)
            conn.sendall(bytes(encrypt_CBC("START", enc_key)))
            if enc_mode == 'CBC':
                while 1:
                    encrypted_text = conn.recv(64)
                    decr_text = decrypt_CBC(encrypted_text, enc_key)
                    print(decr_text)
                    if len(decr_text) == 0:
                        break
                    else:
                        print(decr_text.decode())

            elif enc_mode == "OFB":
                while 1:
                    encrypted_text = conn.recv(64)
                    decr_text = decrypt_OFB(encrypted_text, enc_key)
                    if len(decr_text) == 0:
                        break
                    else:
                        print(decr_text.decode())

            print("\n\nRead all content")

