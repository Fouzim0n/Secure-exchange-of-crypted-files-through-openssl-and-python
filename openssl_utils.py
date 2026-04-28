import base64
import subprocess
import os
import tempfile

### ? AES FUNCTIONS

def generate_aes_key():
    """Génére une clé AES aléatoire"""
    return os.urandom(32)

def encrypt_data_aes(data, key):
    """Chiffre un message avec une clé AES. Retourne iv:encrypted_data"""

    key_hex = key.hex()
    data = data.encode('utf-8')

    iv = os.urandom(16)
    iv_hex = iv.hex()

    result = subprocess.run([
        "openssl", "enc", "-aes-256-cbc", "-nosalt",
        "-K", key_hex,
        "-iv", iv_hex
    ], input=data, capture_output=True, check=True)

    encrypted_data = base64.b64encode(result.stdout).decode('utf-8')

    return f"{iv_hex}:{encrypted_data}"


def decrypt_data_aes(encrypted_data, key):
    """Déchiffre un message avec une clé AES."""

    iv_hex, encrypted_data = encrypted_data.split(":", 1)
    key_hex = key.hex()

    encrypted_data= base64.b64decode(encrypted_data)

    result = subprocess.run([
        "openssl", "enc", "-aes-256-cbc", "-d", "-nosalt",
        "-K", key_hex,
        "-iv", iv_hex
    ], input=encrypted_data, capture_output=True, check=True)

    return result.stdout.decode('utf-8').strip()


### ? RSA FUNCTIONS

def generate_rsa_keys():
    """Génére une paire de clés RSA"""

    private_key = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-outform", "PEM", "-pkeyopt", "rsa_keygen_bits:2048"],
        capture_output=True, check=True
    ).stdout.decode('utf-8')

    public_key = subprocess.run(
        ["openssl", "rsa", "-pubout", "-outform", "PEM"],
        input=private_key.encode(), capture_output=True, check=True
    ).stdout.decode('utf-8')

    return private_key, public_key


def encrypt_key_rsa(key, certificat):
    """Chiffre la clé symétrique avec la clé publique extraite du certificat."""

    #creation de fichier temporaire pour contenir le certificat
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_file:
        cert_file.write(certificat.encode())
        cert_path = cert_file.name

    result = subprocess.run(
        ["openssl", "pkeyutl", "-encrypt", "-certin", "-inkey", cert_path,
            "-pkeyopt", "rsa_padding_mode:oaep"],
        input=key,   # key is already bytes (raw AES key)
        capture_output=True, check=True
    )
    
    os.unlink(cert_path) # on efface le fichier

    encrypted_key= base64.b64encode(result.stdout).decode('utf-8')
    return encrypted_key


def decrypt_key_rsa(encrypted_key_b64, private_key):
    """Déchiffre la clé symétrique avec la clé privée RSA."""

    encrypted_key = base64.b64decode(encrypted_key_b64)

    #creation de fichier temporaire pour contenir la private key
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as key_file:
        key_file.write(private_key.encode())
        key_path = key_file.name

    
    result = subprocess.run([
        "openssl", "pkeyutl", "-decrypt",
        "-inkey", key_path,
        "-pkeyopt", "rsa_padding_mode:oaep"
    ], input=encrypted_key, capture_output=True, check=True)

    os.unlink(key_path)# on efface le fichier temp

    return result.stdout


### ? CERTIFICATE FUNCTIONS

def create_certificate(private_key):
    """Crée un certificat auto-signé à partir de la clé privée et retourne le certificat sous format PEM."""

    # creation de fichier temporaire pour contenir la private key
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as key_file:
        key_file.write(private_key.encode())
        key_path = key_file.name

    # Generation de requete de signature de certficat
    csr = subprocess.run(
        ["openssl", "req", "-new", "-key", key_path, "-subj", "/CN=target_server"],
        capture_output=True, check=True
    ).stdout

    # signature du certificat avec la clé privée
    certificate = subprocess.run(
        ["openssl", "x509", "-req", "-days", "10", "-signkey", key_path],
        input=csr, capture_output=True, check=True
    ).stdout.decode('utf-8')

    os.unlink(key_path)# on efface le fichier temporaire

    return certificate

def get_certificate_subject(certificate):
    '''returns the subject name of the certificate'''
    result = subprocess.run(
        ["openssl", "x509", "-noout", "-subject"],
        input=certificate.strip(),
        capture_output=True,
        text=True
    )

    return result.stdout.strip()

def certificate_is_valid(certificate):
    '''verifys if certificate has expired or not'''

    #fichier temporaire pour stocker le certificat
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
        f.write(certificate.encode())
        cert_path = f.name

    result = subprocess.run(
        ["openssl", "verify", "-CAfile", cert_path, cert_path],
        capture_output=True, text=True
    )

    os.unlink(cert_path)#suppression du fichier

    if (result.returncode == 0):
        return True
    
    return False

