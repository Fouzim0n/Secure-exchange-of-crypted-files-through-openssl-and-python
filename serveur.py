import socket
import openssl_utils as ou

# configuration socket
HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Le serveur ecoute sur {HOST}:{PORT}...")

    conn, addr = s.accept()

    with conn:

        # generation des clés RSA et du certificat
        private_key, public_key = ou.generate_rsa_keys()

        certificate = ou.create_certificate(private_key)

        conn.sendall(certificate.encode())
    
        print("Certificat envoyé au client.")

        # obtention de clé de session
        encrypted_key = conn.recv(4096).decode('utf-8')
        session_key = ou.decrypt_key_rsa(encrypted_key, private_key)

        print("\nUne connexion sécurisée a été établie avec le client.\n")

        # ECHANGE DE MESSAGES
        def recevoir_message():
            data = conn.recv(4096).decode('utf-8')
            decrypted = ou.decrypt_data_aes(data, session_key)
            print(f"Message recu [{decrypted}]")
            return decrypted
        
        def envoyer_message(message):
            message_encrypted = ou.encrypt_data_aes(message, session_key)
            conn.sendall(message_encrypted.encode())
            print(f"Message envoyé ["+message+"].")


        message = recevoir_message()
        envoyer_message("Hello to you as well!")
        
        

