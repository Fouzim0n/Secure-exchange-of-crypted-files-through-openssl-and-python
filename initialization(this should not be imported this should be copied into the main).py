import client as cl
import serveur as se
import threading
 
# la configuration
HOST = '127.0.0.1'
PORT = 65432
target_server_name = "target_server"

#initialization variables
serv= None
cli= None

server_ready= threading.Semaphore(0)
connexion_established= threading.Semaphore(0)

#lance lance le client et le serveur dans des threads séparés
def create_server():
    global serv
    serv= se.Server(HOST, PORT, server_ready)
    connexion_established.release()  # Indiquer que la connexion est établie pour le main
def create_client():
    server_ready.acquire()  # Attendre que le serveur soit prêt
    global cli
    cli= cl.Client(HOST, PORT, target_server_name)
    connexion_established.release()

init1 = threading.Thread(target=create_server)
init2 = threading.Thread(target=create_client)
init1.start()
init2.start()

# Attends que la connexion soit établie avant de continuer
connexion_established.acquire()  
connexion_established.acquire()

