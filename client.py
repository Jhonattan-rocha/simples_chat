import socket
import threading
import sys
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
from cryptography.fernet import Fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import struct

HOST =  "127.0.0.1"
PORT = 8080
BYTES = 2048
DARK_GREY = '#121212'
MEDIUM_GREY = '#1F1B24'
OCEAN_BLUE = '#464EB8'
WHITE = "white"
FONT = ("Helvetica", 17)
BUTTON_FONT = ("Helvetica", 15)
SMALL_FONT = ("Helvetica", 13)


class Client(threading.Thread):
    def __init__(self, HOST, PORT, BYTES) -> None:
        threading.Thread.__init__(self)
        self.HOST = HOST
        self.PORT = PORT
        self.BYTES = BYTES
        self.key = None
        self.fernet = None
        self.public_key = None
        self.private_key = None

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

    def decrypt_large_message(self, encrypted_blocks):
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
                                #testa se o que falta é menor que 2048, pois é o máximo, se não for menor, ele sempre lerá 20248 até acabar
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
    
    def set_crypt_key(self, client: socket.socket):
        self.generate_key_pair()
        client.sendall(self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        fer_key = client.recv(2048)
        self.key = self.decrypt_key_with_private_key(fer_key, self.private_key)
        self.fernet = Fernet(self.key)
    
    def connect(self, client):
        user = self.username_textbox.get().encode()
        if user:
            client.connect((HOST, PORT))
        
            self.set_crypt_key(client)
        
            self.send_message(client, self.encrypt_large_message(user))
            
            threading.Thread(target=self.listen_messages, args=(client, )).start()
            
            print(user)

    def add_message(self, message):
        self.message_box.config(state=tk.NORMAL)
        self.message_box.insert(tk.END, message + '\n')
        self.message_box.config(state=tk.DISABLED)
        
    def send_message_from_GUI(self, client: socket.socket):
        mes = self.message_textbox.get().encode()
        self.send_message(client, self.encrypt_large_message(mes))
        self.message_textbox.delete(0, len(mes))
    
    def listen_messages(self, client: socket.socket):
        while True:
            message = self.receive_message(client)

            self.add_message(self.decrypt_large_message(message).decode())
    
    def on_closing(self, client: socket.socket):
        if tk.messagebox.askokcancel("Fechar", "Deseja realmente fechar a aplicação?"):
            client.close()
            self.root.destroy()
    
    def run(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            try:
                self.root = tk.Tk()
                self.root.geometry("600x600")
                self.root.title("Messenger Client")
                self.root.resizable(False, False)
                self.root.protocol("WM_DELETE_WINDOW", lambda : self.on_closing(client))
                self.root.grid_rowconfigure(0, weight=1)
                self.root.grid_rowconfigure(1, weight=4)
                self.root.grid_rowconfigure(2, weight=1)

                self.top_frame = tk.Frame(self.root, width=600, height=100, bg=DARK_GREY)
                self.top_frame.grid(row=0, column=0, sticky=tk.NSEW)

                self.middle_frame = tk.Frame(self.root, width=600, height=400, bg=MEDIUM_GREY)
                self.middle_frame.grid(row=1, column=0, sticky=tk.NSEW)

                self.bottom_frame = tk.Frame(self.root, width=600, height=100, bg=DARK_GREY)
                self.bottom_frame.grid(row=2, column=0, sticky=tk.NSEW)

                self.username_label = tk.Label(self.top_frame, text="Enter username:", font=FONT, bg=DARK_GREY, fg=WHITE)
                self.username_label.pack(side=tk.LEFT, padx=10)

                self.username_textbox = tk.Entry(self.top_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=23)
                self.username_textbox.pack(side=tk.LEFT)

                self.username_button = tk.Button(self.top_frame, text="Join", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=lambda : self.connect(client))
                self.username_button.pack(side=tk.LEFT, padx=15)

                self.message_textbox = tk.Entry(self.bottom_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=38)
                self.message_textbox.pack(side=tk.LEFT, padx=10)

                self.message_button = tk.Button(self.bottom_frame, text="Send", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=lambda : self.send_message_from_GUI(client))
                self.message_button.pack(side=tk.LEFT, padx=10)

                self.message_box = scrolledtext.ScrolledText(self.middle_frame, font=SMALL_FONT, bg=MEDIUM_GREY, fg=WHITE, width=67, height=26.5)
                self.message_box.config(state=tk.DISABLED)
                self.message_box.pack(side=tk.TOP)
                
                self.root.mainloop()
          
            except KeyboardInterrupt as e:
                print(e)
                sys.exit(1)
            except Exception as e:
                print(e)
                sys.exit(1)


client = Client(HOST, PORT, BYTES)
client.start()
