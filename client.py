import socket
import openssl_utils as ou

# Server info
HOST = '127.0.0.1'
PORT = 65432
target_server_name = "target_server"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

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
    session_key = ou.generate_aes_key()
    encrypted_session_key = ou.encrypt_key_rsa(session_key, server_certificate)

    s.sendall(encrypted_session_key.encode())

    print("Une connexion sécurisée a été établie avec le serveur.\n")

    # ECHANGE DE MESSAGES
    def envoyer_message(message):
        message_encrypted = ou.encrypt_data_aes(message, session_key)
        s.sendall(message_encrypted.encode())
        print(f"Message envoyé ["+message+"].")

    def recevoir_message():
        data = s.recv(4096).decode('utf-8')
        decrypted = ou.decrypt_data_aes(data, session_key)
        print(f"Message recu [{decrypted}]")
        return decrypted


    envoyer_message("Hello")
    message= recevoir_message()
    
