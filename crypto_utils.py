import os
import base64
import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

# AES functions

def generate_aes_key():
    """Generate a random 32-byte AES key."""
    return os.urandom(32)


def encrypt_data_aes(data, key):
    """Encrypt a UTF-8 string with AES-256-CBC. Returns iv_hex:base64(ciphertext)"""
    if isinstance(data, str):
        data = data.encode('utf-8')

    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()

    return f"{iv.hex()}:{base64.b64encode(ct).decode('utf-8')}"


def decrypt_data_aes(encrypted_data, key):
    """Decrypt iv_hex:base64(ciphertext) and return UTF-8 string."""
    iv_hex, ct_b64 = encrypted_data.split(':', 1)
    iv = bytes.fromhex(iv_hex)
    ct = base64.b64decode(ct_b64)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()
    return data.decode('utf-8')

# RSA functions

def generate_rsa_keys():
    """Generate RSA private and public keys (PEM strings)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return priv_pem, pub_pem


def encrypt_key_rsa(key, certificate_pem):
    """Encrypt raw key bytes using public key extracted from certificate PEM. Returns base64 string."""
    cert = x509.load_pem_x509_certificate(certificate_pem.encode(), default_backend())
    public_key = cert.public_key()
    ct = public_key.encrypt(
        key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ct).decode('utf-8')


def decrypt_key_rsa(encrypted_key_b64, private_key_pem):
    """Decrypt base64-encoded encrypted key using private key PEM. Returns raw bytes."""
    encrypted_key = base64.b64decode(encrypted_key_b64)
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return key

# Certificate functions

def create_certificate(private_key_pem, common_name='target_server'):
    """Create a self-signed certificate PEM from a private key PEM. Returns certificate PEM string."""
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.utcnow()
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=10)
    ).sign(private_key, hashes.SHA256(), default_backend())

    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')


def get_certificate_subject(certificate_pem):
    """Return subject in the format 'subject=CN=...' to mimic openssl output."""
    cert = x509.load_pem_x509_certificate(certificate_pem.encode(), default_backend())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return f"subject=CN={cn}"


def certificate_is_valid(certificate_pem):
    """Check certificate validity (dates and self-signature)."""
    try:
        cert = x509.load_pem_x509_certificate(certificate_pem.encode(), default_backend())
        now = datetime.datetime.utcnow()
        if now < cert.not_valid_before or now > cert.not_valid_after:
            return False

        # verify signature with public key (for self-signed cert this should succeed)
        public_key = cert.public_key()
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False
