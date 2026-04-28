import socket
import threading
import openssl_utils as ou

# configuration socket
HOST = '127.0.0.1'
PORT = 65432

 
class Server:
    session_key = None
    connection= None

    def __init__(self, HOST, PORT, server_ready):

        s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #configuration du socket et attente de connexion
        s.bind((HOST, PORT))
        s.listen()
        s.settimeout(60)
        self.server_socket = s
        server_ready.release()  # Indiquer que le serveur est prêt


        print(f"Le serveur ecoute sur {HOST}:{PORT}...")

        conn, addr = s.accept()


        # generation des clés RSA et du certificat
        private_key, public_key = ou.generate_rsa_keys()

        certificate = ou.create_certificate(private_key)

        conn.sendall(certificate.encode())
    
        print("Certificat envoyé au client.")

        # obtention de clé de session
        encrypted_key = conn.recv(4096).decode('utf-8')
        self.session_key = ou.decrypt_key_rsa(encrypted_key, private_key)

        print("\nUne connexion sécurisée a été établie avec le client.\n")
        self.connection= conn
          # Indiquer que la connexion est établie pour le main

                
    def recevoir_message(self):
        data = self.connection.recv(4096).decode('utf-8') #type: ignore
        decrypted = ou.decrypt_data_aes(data, self.session_key)
        print(f"Message recu [{decrypted}]")
        return decrypted
        
    def envoyer_message(self, message):
        message_encrypted = ou.encrypt_data_aes(message, self.session_key)
        self.connection.sendall(message_encrypted.encode()) #type: ignore
        print(f"Message envoyé ["+message+"].")

    def test(self):
        message = self.recevoir_message()
        self.envoyer_message("Hello to you as well!")
    
        

