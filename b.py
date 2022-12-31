import socket, random, base64, traceback
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


ADDR = ('127.0.0.1', 5050)
CONNECTIONS = dict()
PRIVATE_KEY = rsa.generate_private_key(65537, 2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()
PUBLIC_KEY_A = None
ID = None
N1 = None
N2 = None


def receive_input(conn):
    client_input = conn.recv(2048)
    client_input = client_input.decode().rstrip()
    return client_input


def nonce_generator():
	num = ""
	for i in range(10):
		rand = random.randint(0,1)
		num += str(rand)
	return num


def decrypt(chipertext, KEY):
    return KEY.decrypt(
        chipertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    

def custom_public_key_decrypt(ks, KEY):
    if KEY is None:
        raise ValueError("No public key available")
    if not 0 <= ks < KEY.public_numbers().n:
        raise ValueError("Message too large")
    return int(pow(ks, KEY.public_numbers().e, KEY.public_numbers().n))


def decrypt_with_symmetric_key(message):
    key_message = message[:256]
    key_message_decrypt = decrypt(key_message, PRIVATE_KEY)
    iv_message = message[256:]
    iv_message_decrypt = decrypt(iv_message, PRIVATE_KEY)
    cipher = Cipher(
        algorithms.AES(key_message_decrypt), 
        modes.CBC(iv_message_decrypt)
    )

    return cipher.decryptor()


def get_a_public_key(message):
    message = message.decode("utf-8")
    b64data = '\n'.join(message.splitlines()[1:-1])
    derdata = base64.b64decode(b64data)
    pua = load_der_public_key(derdata, default_backend())
    return pua


def get_n_value(ciphertext):
    decrypted_message = b''
    decrypted_message += PRIVATE_KEY.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message[0:10].decode()


def handle_client(conn, addr, client_id):
    print("[ACK]     Assigning ID", client_id, "to ", addr[0], ":", addr[1])
    conn.send(CONNECTIONS[conn.getpeername()].encode())

    while True:
        first_input = receive_input(conn)
        if "quit" in first_input:
            CONNECTIONS[conn.getpeername()] = None
            conn.close()
            print("[DISC]    Client", client_id, "disconnected.")
            break

        elif "connect" in first_input:
            print("[SEND]    Sending public key to ", client_id)
            public_key_pem = PUBLIC_KEY.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            conn.send(public_key_pem)

            first_encrypted_message = conn.recv(2048)
            N1 = get_n_value(first_encrypted_message)
            N2 = nonce_generator()
            content = (N1 + N2).encode()

            public_key_a_pem = conn.recv(2048)
            PUBLIC_KEY_A = get_a_public_key(public_key_a_pem)

            second_encrypted_message = PUBLIC_KEY_A.encrypt(
                content,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("[SEND]    Sending encrypted message to ", client_id)
            conn.send(second_encrypted_message)

            third_encrypted_message = conn.recv(2048)
            n2_from_a = get_n_value(third_encrypted_message)

            if n2_from_a == N2:
                print("[SUCCESS] Authentication is successful")
                conn.send("VERIFIED".encode())

                second_input = receive_input(conn)

                if "send" in second_input:
                    symmetric_content = conn.recv(2048)
                    key_and_iv_symmetric_content = symmetric_content[256:]
                    decryptor = decrypt_with_symmetric_key(key_and_iv_symmetric_content)

                    key_secret_in_bytes = decryptor.update(symmetric_content[:256]) + decryptor.finalize()
                    key_secret_in_int = int.from_bytes(key_secret_in_bytes, 'big')
                    key_secret = custom_public_key_decrypt(key_secret_in_int, PUBLIC_KEY_A)
                    print(f"[RECV]    Key secret {key_secret} is received successfully\n")

                elif "quit" in second_input:
                    CONNECTIONS[conn.getpeername()] = None
                    conn.close()
                    print("[DISC]    Client", client_id, "disconnected.")
                    break
                
                else :
                    pass

            else :
                print("[FAILED]    Authentication fails")
                conn.close()
        else:
            pass


def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)

    print("[WAIT]    Waiting for connection...")
    server.listen(2)

    no_of_connection = 0

    while True:
        conn, addr = server.accept()
        new_id = None
        print("[ACK]     Incoming connection from: ", addr)

        if conn.getpeername() not in CONNECTIONS.keys():
            no_of_connection += 1
            new_id = str(no_of_connection).zfill(8)
            CONNECTIONS[conn.getpeername()] = new_id
        try:
            Thread(
                target=handle_client, 
                args=(conn, addr, new_id)
            ).start()
        except:
            print("Thread did not start.")
            traceback.print_exc()


if __name__ == '__main__':
    print("[START]   Server is starting...")
    start()