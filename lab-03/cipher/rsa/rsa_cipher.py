#class rsa_cipher.py class
import rsa
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, 'keys')

PRIVATE_KEY_FILE = os.path.join(KEYS_DIR, 'private_key.pem')
PUBLIC_KEY_FILE = os.path.join(KEYS_DIR, 'public_key.pem')

class RSACipher:
    def __init__(self):
        if not os.path.exists(KEYS_DIR):
            os.makedirs(KEYS_DIR)
        pass

    def generate_keys(self):
        public_key, private_key = rsa.newkeys(2048)
        
        with open(PRIVATE_KEY_FILE, 'wb') as f:
            f.write(private_key.save_pkcs1())
            
        with open(PUBLIC_KEY_FILE, 'wb') as f:
            f.write(public_key.save_pkcs1())
            
        return True

    def load_keys(self):
        private_key = None
        public_key = None
        
        if os.path.exists(PRIVATE_KEY_FILE):
            with open(PRIVATE_KEY_FILE, 'rb') as f:
                private_key = rsa.PrivateKey.load_pkcs1(f.read())
                
        if os.path.exists(PUBLIC_KEY_FILE):
            with open(PUBLIC_KEY_FILE, 'rb') as f:
                public_key = rsa.PublicKey.load_pkcs1(f.read())
                
        return private_key, public_key

    def encrypt(self, message, public_key):
        message_bytes = message.encode('utf-8')
        ciphertext = rsa.encrypt(message_bytes, public_key)
        return ciphertext

    def decrypt(self, ciphertext, private_key):
        decrypted_message_bytes = rsa.decrypt(ciphertext, private_key)
        return decrypted_message_bytes.decode('utf-8')

    def sign(self, message, private_key):
        message_bytes = message.encode('utf-8')
        signature = rsa.sign(message_bytes, private_key, 'SHA-256')
        return signature

    def verify(self, message, signature, public_key):
        message_bytes = message.encode('utf-8')
        try:
            rsa.verify(message_bytes, signature, public_key)
            return True
        except rsa.VerificationError:
            return False
        except Exception:
            return False