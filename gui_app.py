import threading
import socket
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext
import openssl_utils as ou

HOST = '127.0.0.1'
PORT = 65432

class SecureGUI:
    def __init__(self, root):
        self.root = root
        root.title('Secure Exchange - Client / Server')
        self.server_queue = queue.Queue()
        self.client_queue = queue.Queue()

        self.server_socket = None
        self.client_socket = None
        self.server_session_key = None
        self.client_session_key = None
        self.server_thread = None
        self.client_thread = None
        # flags for plaintext fallback mode
        self.client_plaintext = False
        self.server_plaintext = False

        self._build_ui()
        self._poll_queues()

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill='both', expand=True)

        panes = ttk.PanedWindow(main, orient='horizontal')
        panes.pack(fill='both', expand=True)


        server_frame = ttk.Labelframe(panes, text='Server', padding=8)
        panes.add(server_frame, weight=1)

        self.server_log = scrolledtext.ScrolledText(server_frame, width=50, height=20, state='disabled')
        self.server_log.pack(fill='both', expand=True)

        self.server_log.configure(bg='#23262e', fg='white', insertbackground='white', bd=0)

        srv_controls = ttk.Frame(server_frame)
        srv_controls.pack(fill='x', pady=(8, 0))


        self.server_input = tk.Entry(srv_controls, bg='#39404b', fg='white', insertbackground='white', relief='flat')
        self.server_input.pack(side='left', fill='x', expand=True, padx=(0, 8))
        ttk.Button(srv_controls, text='OK', command=self.server_ok).pack(side='left')
        ttk.Button(srv_controls, text='Start Server', command=self.start_server).pack(side='left', padx=(8,0))


        client_frame = ttk.Labelframe(panes, text='Client', padding=8)
        panes.add(client_frame, weight=1)

        self.client_log = scrolledtext.ScrolledText(client_frame, width=50, height=20, state='disabled')
        self.client_log.pack(fill='both', expand=True)

        self.client_log.configure(bg='#23262e', fg='white', insertbackground='white', bd=0)

        cli_controls = ttk.Frame(client_frame)
        cli_controls.pack(fill='x', pady=(8, 0))


        self.client_input = tk.Entry(cli_controls, bg='#39404b', fg='white', insertbackground='white', relief='flat')
        self.client_input.pack(side='left', fill='x', expand=True, padx=(0, 8))
        ttk.Button(cli_controls, text='OK', command=self.client_ok).pack(side='left')
        ttk.Button(cli_controls, text='Connect Client', command=self.start_client).pack(side='left', padx=(8,0))

    def _append_server_log(self, text):
        self.server_log.configure(state='normal')
        self.server_log.insert('end', text + '\n')
        self.server_log.configure(state='disabled')
        self.server_log.see('end')

    def _append_client_log(self, text):
        self.client_log.configure(state='normal')
        self.client_log.insert('end', text + '\n')
        self.client_log.configure(state='disabled')
        self.client_log.see('end')

    def _poll_queues(self):
        try:
            while True:
                msg = self.server_queue.get_nowait()
                self._append_server_log(msg)
        except queue.Empty:
            pass

        try:
            while True:
                msg = self.client_queue.get_nowait()
                self._append_client_log(msg)
        except queue.Empty:
            pass

        self.root.after(100, self._poll_queues)


    def start_server(self):
        if self.server_thread and self.server_thread.is_alive():
            self.server_queue.put('Server already running')
            return
        self.server_thread = threading.Thread(target=self._server_worker, daemon=True)
        self.server_thread.start()
        self.server_queue.put('Starting server thread...')

    def _server_worker(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen(1)
            self.server_queue.put(f'Server listening on {HOST}:{PORT}')
            conn, addr = s.accept()
            with conn:
                self.server_queue.put(f'Client connected: {addr}')


                secure_mode = True
                try:
                    private_key, public_key = ou.generate_rsa_keys()
                    certificate = ou.create_certificate(private_key)
                    conn.sendall(certificate.encode())
                    self.server_queue.put('Certificate sent to client')

                    encrypted_key = conn.recv(4096).decode('utf-8')
                    self.server_session_key = ou.decrypt_key_rsa(encrypted_key, private_key)
                    self.server_queue.put('Session key received and decrypted')
                    self.server_plaintext = False
                except Exception as e:
                    secure_mode = False
                    self.server_plaintext = True
                    self.server_queue.put('Secure crypto not available; falling back to plaintext mode: ' + str(e))
                    conn.sendall(b'PLAINTEXT')

                if secure_mode:
                    def recevoir_message():
                        data = conn.recv(4096).decode('utf-8')
                        decrypted = ou.decrypt_data_aes(data, self.server_session_key)
                        self.server_queue.put(f"Message recu [{decrypted}]")
                        return decrypted

                    def envoyer_message(message):
                        message_encrypted = ou.encrypt_data_aes(message, self.server_session_key)
                        conn.sendall(message_encrypted.encode())
                        self.server_queue.put(f"Message envoyé [{message}].")


                    message = recevoir_message()
                    envoyer_message(f"{message} to u as well")


                    while True:
                        data = conn.recv(4096)
                        if not data:
                            self.server_queue.put('Client disconnected')
                            break
                        try:
                            data = data.decode('utf-8')
                            decrypted = ou.decrypt_data_aes(data, self.server_session_key)
                            self.server_queue.put('Received (client): ' + decrypted)

                            reply = 'Server echo: ' + decrypted
                            encrypted_reply = ou.encrypt_data_aes(reply, self.server_session_key)
                            conn.sendall(encrypted_reply.encode())
                            self.server_queue.put('Sent (server): ' + reply)
                        except Exception as e:
                            self.server_queue.put('Server error: ' + str(e))
                            break
                else:

                    def recevoir_message():
                        data = conn.recv(4096).decode('utf-8')
                        self.server_queue.put(f"Message recu [{data}]")
                        return data

                    def envoyer_message(message):
                        conn.sendall(message.encode())
                        self.server_queue.put(f"Message envoyé [{message}].")

                    message = recevoir_message()
                    envoyer_message(f"{message} to u as well")

                    while True:
                        data = conn.recv(4096)
                        if not data:
                            self.server_queue.put('Client disconnected')
                            break
                        try:
                            data = data.decode('utf-8')
                            self.server_queue.put('Received (client): ' + data)

                            reply = 'Server echo: ' + data
                            conn.sendall(reply.encode())
                            self.server_queue.put('Sent (server): ' + reply)
                        except Exception as e:
                            self.server_queue.put('Server error: ' + str(e))
                            break

    def server_ok(self):
        text = self.server_input.get().strip()
        if not text:
            return

        self.server_queue.put('Local server message (not networked): ' + text)
        self.server_input.delete(0, 'end')

    # Client logic
    def start_client(self):
        if self.client_thread and self.client_thread.is_alive():
            self.client_queue.put('Client already running')
            return
        # capture initial message from entry for the automatic initial exchange
        self.initial_client_message = self.client_input.get().strip() or "Hello"
        self.client_thread = threading.Thread(target=self._client_worker, daemon=True)
        self.client_thread.start()
        self.client_queue.put('Starting client thread...')

    def _client_worker(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, PORT))
            self.client_socket = s
            self.client_queue.put(f'Connected to server {HOST}:{PORT}')

            server_certificate = s.recv(4096)
            try:
                server_certificate_text = server_certificate.decode('utf-8')
            except Exception:
                server_certificate_text = ''

            if server_certificate_text.strip() == 'PLAINTEXT':
                # plaintext fallback
                self.client_queue.put('Server running in plaintext mode (no openssl)')
                self.client_session_key = None
                self.client_plaintext = True

                def envoyer_message(message):
                    s.sendall(message.encode())
                    self.client_queue.put('Sent (client): ' + message)

                def recevoir_message():
                    data = s.recv(4096).decode('utf-8')
                    self.client_queue.put('Received (server): ' + data)
                    return data

                try:
                    envoyer_message(self.initial_client_message)
                    recevoir_message()
                except Exception as e:
                    self.client_queue.put('Initial exchange error (plaintext): ' + str(e))

                while True:
                    data = s.recv(4096)
                    if not data:
                        self.client_queue.put('Server closed connection')
                        break
                    try:
                        data = data.decode('utf-8')
                        self.client_queue.put('Received (server): ' + data)
                    except Exception as e:
                        self.client_queue.put('Client error: ' + str(e))
                        break
            else:
                # secure path
                server_certificate = server_certificate_text
                subject = ou.get_certificate_subject(server_certificate)
                if subject == 'subject=CN=target_server' and ou.certificate_is_valid(server_certificate):
                    self.client_queue.put('Certificate validated')
                else:
                    self.client_queue.put('Bad certificate - aborting')
                    s.close()
                    return

                self.client_session_key = ou.generate_aes_key()
                encrypted_session_key = ou.encrypt_key_rsa(self.client_session_key, server_certificate)
                s.sendall(encrypted_session_key.encode())
                self.client_queue.put('Session key sent (encrypted)')
                self.client_plaintext = False

                def envoyer_message(message):
                    encrypted = ou.encrypt_data_aes(message, self.client_session_key)
                    s.sendall(encrypted.encode())
                    self.client_queue.put('Sent (client): ' + message)

                def recevoir_message():
                    data = s.recv(4096).decode('utf-8')
                    decrypted = ou.decrypt_data_aes(data, self.client_session_key)
                    self.client_queue.put('Received (server): ' + decrypted)
                    return decrypted

                try:
                    envoyer_message(self.initial_client_message)
                    recevoir_message()
                except Exception as e:
                    self.client_queue.put('Initial exchange error: ' + str(e))

                # then continue listening for server messages
                while True:
                    data = s.recv(4096)
                    if not data:
                        self.client_queue.put('Server closed connection')
                        break
                    try:
                        data = data.decode('utf-8')
                        decrypted = ou.decrypt_data_aes(data, self.client_session_key)
                        self.client_queue.put('Received (server): ' + decrypted)
                    except Exception as e:
                        self.client_queue.put('Client error: ' + str(e))
                        break

        except Exception as e:
            self.client_queue.put('Client connection error: ' + str(e))

    def client_ok(self):
        text = self.client_input.get().strip()
        if not text:
            return
        if not self.client_socket:
            self.client_queue.put('Not connected')
            return
        try:
            if self.client_session_key:
                encrypted = ou.encrypt_data_aes(text, self.client_session_key)
                self.client_socket.sendall(encrypted.encode())
            elif self.client_plaintext:
                self.client_socket.sendall(text.encode())
            else:
                self.client_queue.put('Not connected or crypto not negotiated')
                return

            self.client_queue.put('Sent (client): ' + text)
            self.client_input.delete(0, 'end')
        except Exception as e:
            self.client_queue.put('Send error: ' + str(e))

if __name__ == '__main__':
    root = tk.Tk()
    style = ttk.Style(root)
    try:
        style.theme_use('clam')
    except Exception:
        pass

    # Dark theme colors
    bg = '#2a2e39'      # user requested background
    fg = 'white'
    accent = '#4db6ac'  # complementary accent

    # General ttk styles
    style.configure('.', background=bg, foreground=fg)
    style.configure('TFrame', background=bg)
    style.configure('TLabelframe', background=bg, foreground=fg)
    style.configure('TLabelframe.Label', background=bg, foreground=fg)
    style.configure('TLabel', background=bg, foreground=fg)
    style.configure('TButton', background=accent, foreground=fg)
    style.map('TButton', background=[('active', '#3aa79a')])
    style.configure('TEntry', fieldbackground='#39404b', foreground=fg)

    root.configure(bg=bg)

    app = SecureGUI(root)
    root.mainloop()
