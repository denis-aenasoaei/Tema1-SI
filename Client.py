import socket
from Crypto.Cipher import AES



HOST_SRV = '127.0.0.1'  # The server's hostname or IP address
PORT_SRV = 65421       # The port used by the server


HOST_KM = '127.0.0.1'  # The server's hostname or IP address
PORT_KM = 65433        # The port used by the server

enc_type = input("Please insert encryption type (CBC or OFB)\n")
enc_type = enc_type.upper()
if enc_type != 'CBC' and enc_type != 'OFB':
    exit()

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
    for i in range(nb_blocks):
            enc2 = xor_for_char(plainText[i * 16:(i + 1) * 16], iv)
            iv = cipher.encrypt(enc2)
            cypherText += iv
    #print(codecs.decode(codecs.encode(cypherText,'base64')).replace("\n", ""))
    return cypherText


def decrypt_CBC(cypherText, key):
    nb_blocks = (int) (len(cypherText)/16)
    byteText = bytearray()
    iv = IV
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(nb_blocks):
        enc2 = cipher.decrypt(cypherText[i*16:(i+1) * 16])
        byteText += xor_for_char(iv, enc2)
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

def decrypt_OFB (cypherText, key):
    nb_blocks = (int) (len(cypherText)/16)
    byteText = bytearray()
    iv = IV
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(nb_blocks):
        iv = cipher.encrypt(iv)
        byteText += xor_for_char(iv, cypherText[i*16:(i+1) * 16])
    return unpad_data(byteText)

#Get Key  from key manager and decrypt it

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST_KM, PORT_KM))
    cryptedKey = s.recv(16)
    enc_key = decrypt_CBC(cryptedKey, KEY_FOR_KEYS)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST_SRV, PORT_SRV))
    s.sendall(enc_type.encode())
    s.sendall(cryptedKey)
    if enc_type == "CBC":
        answ = decrypt_CBC(s.recv(16), enc_key)
    elif enc_type == "OFB":
        answ = decrypt_CBC(s.recv(16), enc_key)
    print(answ.decode())
    if answ.decode() == "START":
        with open("test.txt", "r") as f:
            while 1:
                text = f.read(50)
                print(text)
                if text == '':
                    break
                if enc_type == "CBC":
                    s.sendall(encrypt_CBC(text, enc_key))
                elif enc_type == "OFB":
                    s.sendall(encrypt_OFB(text, enc_key))
        s.sendall(encrypt_CBC("STOP", enc_key))
