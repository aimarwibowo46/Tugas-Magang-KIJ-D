import socket, random, sys, os, base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES


ADDR = ('127.0.0.1', 5050)
ID = None 
N1 = None
N2 = None

PRIVATE_KEY = rsa.generate_private_key(65537, 2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()
PUBLIC_KEY_B = None


def print_menu_options():
    print("Options:")
    print("\t Enter 'connect' to connect to server")
    print("\t Enter 'quit' to exit")


def print_menu_options_after_connect():
    print("\t Enter 'send' to send key secret to server")
    print("\t Enter 'quit' to exit")


def nonce_generator():
	num = ""
	for i in range(10):
		rand = random.randint(0,1)
		num += str(rand)
	return num


def encrypt(plaintext, KEY):
    return KEY.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def custom_private_key_encrypt(ks, KEY):
    if KEY is None:
        raise ValueError("No private key available")
    n = (KEY.private_numbers().p)*(KEY.private_numbers().q)
    if not 0 <= ks < n:
        raise ValueError("Message too large")
    return int(pow(ks, KEY.private_numbers().d , n))


def encrypt_with_symmetric_key(message):
    key = os.urandom(AES.block_size)
    iv = os.urandom(AES.block_size)
    cipher = Cipher(
        algorithms.AES(key), 
        modes.CBC(iv)
    )
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()

    return key, iv, ct


def get_b_public_key(message):
    message = message.decode("utf-8")
    b64data = '\n'.join(message.splitlines()[1:-1])
    derdata = base64.b64decode(b64data)
    pub = load_der_public_key(derdata, default_backend())

    return pub


def get_n2(message):
    decrypted_message = b''
    decrypted_message += PRIVATE_KEY.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    n2 = decrypted_message[10:].decode()
    return n2


if __name__ == '__main__':
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn.connect(ADDR)
    except:
        print("Connection error")
        sys.exit()
    
    ID = conn.recv(2048).decode()


    while True:
        print_menu_options()
        first_input = input(" -> ")
        conn.send(first_input.encode())

        if 'connect' in first_input:
            # STEP 1
            publik_key_b_pem = conn.recv(2048)
            PUBLIC_KEY_B = get_b_public_key(publik_key_b_pem)
            N1 = nonce_generator()
            first_message = (N1 + ID).encode()

            first_encrypted_message= encrypt(first_message, PUBLIC_KEY_B)
            conn.send(first_encrypted_message)
            
            # STEP 2
            public_key_a = PUBLIC_KEY.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            conn.send(public_key_a)

            # STEP 3
            second_encrypted_message = conn.recv(2048)
            N2 = get_n2(second_encrypted_message).encode()

            third_encrypted_message = encrypt(N2, PUBLIC_KEY_B)
            conn.send(third_encrypted_message)

            # STEP 4
            verification = conn.recv(2048)
            if verification.decode() == 'VERIFIED' :
                print_menu_options_after_connect()
                second_input = input(" -> ")
                conn.send(second_input.encode())
                if 'send' in second_input:
                    key_secret = random.randint(0, 2**256 - 1)
                    key_secret_encrypted = custom_private_key_encrypt(key_secret, PRIVATE_KEY)
                    key_secret_encrypted_in_bytes = key_secret_encrypted.to_bytes(256, 'big')

                    symmetric_content = encrypt_with_symmetric_key(key_secret_encrypted_in_bytes)
                    conn.send(symmetric_content[2])

                    key_message = encrypt(symmetric_content[0], PUBLIC_KEY_B)
                    iv_message = encrypt(symmetric_content[1], PUBLIC_KEY_B)

                    combined_message = b''.join([key_message,iv_message])
                    conn.send(combined_message)

                elif 'quit' in second_input :
                    break
                
                else :
                    pass

            else :
                break

        elif 'quit' in first_input :
            break

        else :
            pass