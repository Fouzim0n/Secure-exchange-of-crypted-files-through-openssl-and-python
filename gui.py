import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
import client
import serveur


class SecureExchangeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Exchange - Server & Client")
        self.root.geometry("1400x800")
        
        self.server_instance = None
        self.client_instance = None
        self.server_ready = threading.Semaphore(0)
        self.client_ready = threading.Semaphore(0)
        
        self.setup_ui()
    
    def setup_ui(self):

        #* CONTENEUR PRINCIPAL
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        #* PARTIE SERVEUR
        #panel
        left_frame = ttk.LabelFrame(main_frame, text="SERVER", padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 2))
        
        # bouttons
        server_button_frame = ttk.Frame(left_frame)
        server_button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(server_button_frame, text="Start Server", 
                   command=self.start_server).pack(side=tk.LEFT, padx=2)
        ttk.Button(server_button_frame, text="Send Message", 
                   command=self.server_send_message).pack(side=tk.LEFT, padx=2)
        ttk.Button(server_button_frame, text="Receive Message", 
                   command=self.server_receive_message).pack(side=tk.LEFT, padx=2)
        
        # Server message input
        ttk.Label(left_frame, text="Server Message:").pack(anchor=tk.W)
        self.server_message_input = ttk.Entry(left_frame, width=50)
        self.server_message_input.pack(fill=tk.X, pady=5)
        
        # sortie serveur
        ttk.Label(left_frame, text="Server Output:").pack(anchor=tk.W)
        self.server_output = scrolledtext.ScrolledText(left_frame, height=25, width=50, bg="#2a2e39", fg="white")
        self.server_output.pack(fill=tk.BOTH, expand=True, pady=5)
        
        #*  SEPARATEUR POUR LES DEUX PANELS

        separator = ttk.Separator(main_frame, orient=tk.VERTICAL)
        separator.pack(side=tk.LEFT, fill=tk.Y, padx=2)
        
        #* PARTIE CLIENT 
        # panel
        right_frame = ttk.LabelFrame(main_frame, text="CLIENT", padding=10)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(2, 0))
        
        # bouttons
        client_button_frame = ttk.Frame(right_frame)
        client_button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(client_button_frame, text="Connect to Server", 
                   command=self.start_client).pack(side=tk.LEFT, padx=2)
        ttk.Button(client_button_frame, text="Send Message", 
                   command=self.client_send_message).pack(side=tk.LEFT, padx=2)
        ttk.Button(client_button_frame, text="Receive Message", 
                   command=self.client_receive_message).pack(side=tk.LEFT, padx=2)
        
        # entrée messages client
        ttk.Label(right_frame, text="Client Message:").pack(anchor=tk.W)
        self.client_message_input = ttk.Entry(right_frame, width=50)
        self.client_message_input.pack(fill=tk.X, pady=5)
        
        # sortie client
        ttk.Label(right_frame, text="Client Output:").pack(anchor=tk.W)
        self.client_output = scrolledtext.ScrolledText(right_frame, height=25, width=50, bg="#2a2e39", fg="white")
        self.client_output.pack(fill=tk.BOTH, expand=True, pady=5)
    
    def log_server(self, message):#affiche la sortie du serveur dans le champ de server output
        self.server_output.insert(tk.END, message + "\n")
        self.server_output.see(tk.END)
        self.root.update()
    
    def log_client(self, message):#afficher la sortie dans le champ de client output du client
        self.client_output.insert(tk.END, message + "\n")
        self.client_output.see(tk.END)
        self.root.update()
    
    def start_server(self):#crée une instance d'un serveur dans un nouveau thread
        try:
            thread = threading.Thread(target=self._server_thread, daemon=True)
            thread.start()
            self.log_server("Starting server...")
        except Exception as e:
            messagebox.showerror("Error", f"Server Error: {str(e)}")
            self.log_server(f"ERROR: {str(e)}")
    
    def _server_thread(self):#la methode qui sera exécutée dans le thread de creation de serveur
        try:
            self.log_server("Waiting for client connection...")
            self.server_instance = serveur.Server('127.0.0.1', 65432, self.server_ready)
            self.log_server("Client connected - Server ready")
        except socket.timeout:
            self.log_server("ERROR: Connection timeout (60 seconds)")
        except Exception as e:
            self.log_server(f"ERROR: {str(e)}")
    
    def start_client(self):# crée une instance d'un client dans un nouveau thread
        try:
            thread = threading.Thread(target=self._client_thread, daemon=True)
            thread.start()
            self.log_client("Connexion au serveur...")
        except Exception as e:
            messagebox.showerror("Error", f"Client Error: {str(e)}")
            self.log_client(f"Erreur: {str(e)}")
    
    def _client_thread(self):#la methode qui sera exécutée dans le thread de creation de client
        try:
            self.server_ready.acquire(timeout=65)
            self.log_client("Serveur préts, connexion en cours...")
            self.client_instance = client.Client('127.0.0.1', 65432, 'target_server', self.client_ready)
            self.log_client("Connexion avec succès - Client prêt")
        except socket.timeout:
            self.log_client("ERREUR: Server not non préts (timeout)")
        except Exception as e:
            self.log_client(f"ERROR: {str(e)}")
    
    def server_send_message(self):#fait envoyer un message du serveur
        if not self.server_instance:
            messagebox.showwarning("Warning", "Server not initilizé")
            return
        
        message = self.server_message_input.get()
        if not message:
            messagebox.showwarning("Warning", "Un message doit être entré")
            return
        try:
            self.server_instance.envoyer_message(message)
            self.log_server(f"Sent: {message}")
            self.server_message_input.delete(0, tk.END)
        except Exception as e:
            self.log_server(f"ERROR: {str(e)}")
    
    def server_receive_message(self):#fait recevoir un message au serveur dans un thread séparé
        if not self.server_instance:
            messagebox.showwarning("Warning", "Server not initialized")
            return
        
        thread = threading.Thread(target=self._server_receive_thread, daemon=True)
        thread.start()
    
    def _server_receive_thread(self):#la méthode de reception du message dans le thread
        try:
            message = self.server_instance.recevoir_message()#type: ignore
            self.log_server(f"Received: {message}")
        except Exception as e:
            self.log_server(f"ERROR: {str(e)}")
    
    def client_send_message(self):#fait envoyer un message du client
        if not self.client_instance:
            messagebox.showwarning("Warning", "Client not connected")
            return
        
        message = self.client_message_input.get()
        if not message:
            messagebox.showwarning("Warning", "Enter a message")
            return
        
        try:
            self.client_instance.envoyer_message(message)
            self.log_client(f"Envoyé: {message}")
            self.client_message_input.delete(0, tk.END)
        except Exception as e:
            self.log_client(f"ERREUR: {str(e)}")
    
    def client_receive_message(self):#fait recevoir un message au client
        if not self.client_instance:
            messagebox.showwarning("Warning", "Client not connected")
            return
        
        thread = threading.Thread(target=self._client_receive_thread, daemon=True)
        thread.start()
    
    def _client_receive_thread(self): #la méthode de reception du message dans le thread
        try:
            message = self.client_instance.recevoir_message()#type: ignore
            self.log_client(f"Recu: {message}")
        except Exception as e:
            self.log_client(f"ERREUR: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    gui = SecureExchangeGUI(root)
    root.mainloop()
