import socket
import threading
import openssl_utils as ou

# Server info
HOST = '127.0.0.1'
PORT = 65432
target_server_name = "target_server"

class Client:
 
    connection= None
    session_key = None

    def __init__(self,HOST, PORT, target_server_name, client_ready= threading.Semaphore(1)):

        s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))

        # reception du certificat et verification de sa validité
        server_certificate = s.recv(4096).decode('utf-8')
        
        subject =ou.get_certificate_subject(server_certificate)

        if (subject == "subject=CN=" + target_server_name and ou.certificate_is_valid(server_certificate)):
            print("Certificat validée.")
        else:
            print("MAUVAIS CERTIFICAT. CONNECTION ABANDONNEE.")
            exit(1)

        # creation et partage de clé de session
        self.session_key = ou.generate_aes_key()
        encrypted_session_key = ou.encrypt_key_rsa(self.session_key, server_certificate)

        s.sendall(encrypted_session_key.encode())

        print("Une connexion sécurisée a été établie avec le serveur.\n")
        self.connection= s

        # indiquer que la connexion est établie pour le main
        client_ready.release()  # Indiquer que la connexion est établie

    # ECHANGE DE MESSAGES
    def envoyer_message(self,message):
        message_encrypted = ou.encrypt_data_aes(message, self.session_key)
        self.connection.sendall(message_encrypted.encode()) #type: ignore
        print(f"Message envoyé ["+message+"].")

    def recevoir_message(self):
        data = self.connection.recv(4096).decode('utf-8')  #type: ignore
        decrypted = ou.decrypt_data_aes(data, self.session_key)
        print(f"Message recu [{decrypted}]")
        return decrypted
            
            

    def test(self):
        self.envoyer_message("Hello")
        message= self.recevoir_message()
            
