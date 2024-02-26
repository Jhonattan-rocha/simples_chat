import socket
import threading
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import struct

HOST = "127.0.0.1"
PORT = 8080


class Server(threading.Thread):
    def __init__(self, HOST, PORT) -> None:
        threading.Thread.__init__(self)
        self.HOST = HOST
        self.PORT = PORT
        self.BYTES = 2048
        self.clients = []
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)
        self.public_key = None
        self.private_key = None
    
    def load_public_key(self, public_key_bytes):
        public_key = serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )
        return public_key
    
    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        self.public_key = public_key
        self.private_key = private_key

    # Função para criptografar a chave do Fernet usando a chave pública
    def encrypt_key_with_public_key(self, fernet_key, public_key):
        encrypted_key = public_key.encrypt(
            fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key

    # Função para descriptografar a chave do Fernet usando a chave privada
    def decrypt_key_with_private_key(self, encrypted_key, private_key):
        fernet_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return fernet_key


    def encrypt_large_message(self, message):
        try:
            return self.fernet.encrypt(message)
        except Exception as e:
            print(e)
            return b""

    def decrypt_large_message(self, encrypted_blocks: bytes):
        try:
            return self.fernet.decrypt(encrypted_blocks)
        except Exception as e:
            print(e)
            return b""
    
    def receive_message(self, sock):
        # primeiro, receba o tamanho da mensagem
        raw_msglen = sock.recv(4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        # em seguida, receba a mensagem em blocos
        chunks = []
        bytes_received = 0
        while bytes_received < msglen:
            chunk = sock.recv(min(msglen - bytes_received, 2048))
            if not chunk:
                raise RuntimeError('Conexão interrompida')
            chunks.append(chunk)
            bytes_received += len(chunk)
        # junte os blocos e retorne a mensagem
        return b" ".join(chunks)

    def send_message(self, sock, message):
        # primeiro, envie o tamanho da mensagem
        msglen = len(message)
        sock.sendall(struct.pack('>I', msglen))
        # em seguida, envie a mensagem em blocos
        offset = 0
        while offset < msglen:
            sent = sock.send(message[offset:offset+2048])
            if not sent:
                raise RuntimeError('Conexão interrompida')
            offset += sent

    def send_file(self, sock, file_path):
        with open(file_path, 'rb') as f:
            file_data = f.read()
        encrypted_data = self.encrypt_large_message(file_data)
        self.send_message(sock, encrypted_data)

    def receive_file(self, sock, file_path):
        encrypted_data = self.receive_message(sock)
        decrypted_data = self.decrypt_large_message(encrypted_data)
        with open(file_path, 'wb') as f:
            f.write(decrypted_data)

    def send_messages(self, message):
        message_bytes = self.encrypt_large_message(message=message)
        for client in self.clients:
            self.send_message(client[1], message_bytes)

    def save_clients(self, client):
        if client not in self.clients:
            self.clients.append(client)
    
    def set_crypt_key(self, client: socket.socket):
        self.generate_key_pair()
        client_public_key = client.recv(2048)
        client_public_key_obj = self.load_public_key(client_public_key)
        enc_key = self.encrypt_key_with_public_key(self.key, client_public_key_obj)
        self.send_message(enc_key)
        
    def client_handle(self, client, address):        
        try: 
            self.set_crypt_key(client)
                        
            while 1:
                data = self.receive_message(client)
                username = self.decrypt_large_message(data)
                print(data, username, self.decrypt_large_message(data))
                if not username:
                    self.send_message(client, self.encrypt_large_message("Nome invalido".encode()))
                    continue
                self.save_clients((username, client))
                self.send_messages(str("SERVER:" + f"{username.decode()} entrou no chat").encode())
                threading.Thread(target=self.listen_message, args=(client, username)).start()
                break
        except Exception as e:
            print(e)
            print('client handle')
            sys.exit(1)


    def run(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:

            server.bind((self.HOST, self.PORT))
            server.listen()
            
            print("Servidor rodando")
            while True:
                (client, address) = server.accept()
                
                print(f"Conexão com o cliente do address {address}")
                try:
                    threading.Thread(target=self.client_handle, args=(client, address)).start()
                except KeyboardInterrupt:
                    sys.exit(1)
                except Exception as e:
                    sys.exit(1)

    def listen_message(self, client, username: bytes):
        with client:
            while True:
                message = self.receive_message(client)
                self.send_messages(f"[{username.decode()}]:[{self.decrypt_large_message(message).decode()}]".encode())     

server = Server(HOST=HOST, PORT=PORT)
server.start()
