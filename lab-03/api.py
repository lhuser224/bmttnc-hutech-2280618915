from flask import Flask, request, jsonify
from cipher.rsa import RSACipher
from cipher.ecc import ECCCipher
import os

app = Flask(__name__)
rsa_cipher = RSACipher()
ecc_cipher = ECCCipher()

@app.route('/api/ecc/generate_keys', methods=['GET'])
def generate_ecc_keys():
    ecc_cipher.generate_keys()
    return jsonify({'message': 'Keys generated successfully'})

@app.route('/api/ecc/sign', methods=['POST'])
def sign_message():
    data = request.json
    if 'message' not in data:
        return jsonify({'error': 'Missing "message" in request body'}), 400        
    message = data['message']    
    private_key, _ = ecc_cipher.load_keys()    
    signature_bytes = ecc_cipher.sign(message, private_key)    
    signature_hex = signature_bytes.hex()    
    return jsonify({'signature': signature_hex})

@app.route('/api/ecc/verify', methods=['POST'])
def verify_signature():
    data = request.json    
    if 'message' not in data or 'signature' not in data:
        return jsonify({'error': 'Missing "message" or "signature" in request body'}), 400        
    message = data['message']
    signature_hex = data['signature']    
    _, public_key = ecc_cipher.load_keys()    
    try:
        signature_bytes = bytes.fromhex(signature_hex)
    except ValueError:
        return jsonify({'error': 'Invalid signature hex format'}), 400        
    is_verified = ecc_cipher.verify(message, signature_bytes, public_key)    
    return jsonify({'is_verified': is_verified})

@app.route('/api/rsa/generate_keys', methods=['GET'])
def rsa_generate_keys():
    try:
        rsa_cipher.generate_keys()
        return jsonify({'message': 'Keys generated and saved successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rsa/encrypt', methods=['POST'])
def rsa_encrypt():
    data = request.json
    message = data.get('message')
    
    if not message:
        return jsonify({'error': 'Message is required'}), 400
        
    private_key, public_key = rsa_cipher.load_keys()
    if not public_key:
        return jsonify({'error': 'Public key not found. Generate keys first.'}), 500

    try:
        ciphertext_bytes = rsa_cipher.encrypt(message, public_key)
        return jsonify({'encrypted_message': ciphertext_bytes.hex()}), 200
    except Exception as e:
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500

@app.route('/api/rsa/decrypt', methods=['POST'])
def rsa_decrypt():
    data = request.json
    ciphertext_hex = data.get('ciphertext')
    
    if not ciphertext_hex:
        return jsonify({'error': 'Ciphertext is required'}), 400
        
    private_key, public_key = rsa_cipher.load_keys()
    if not private_key:
        return jsonify({'error': 'Private key not found. Generate keys first.'}), 500

    try:
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        decrypted_message = rsa_cipher.decrypt(ciphertext_bytes, private_key)
        
        return jsonify({'decrypted_message': decrypted_message}), 200
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

@app.route('/api/rsa/sign', methods=['POST'])
def rsa_sign_message():
    data = request.json
    message = data.get('message')
    
    if not message:
        return jsonify({'error': 'Message is required'}), 400
        
    private_key, public_key = rsa_cipher.load_keys()
    if not private_key:
        return jsonify({'error': 'Private key not found. Generate keys first.'}), 500

    try:
        signature_bytes = rsa_cipher.sign(message, private_key)
        return jsonify({'signature': signature_bytes.hex()}), 200
    except Exception as e:
        return jsonify({'error': f'Signing failed: {str(e)}'}), 500

@app.route('/api/rsa/verify', methods=['POST'])
def rsa_verify_signature():
    data = request.json
    message = data.get('message')
    signature_hex = data.get('signature')
    
    if not message or not signature_hex:
        return jsonify({'error': 'Message and signature are required'}), 400
        
    private_key, public_key = rsa_cipher.load_keys()
    if not public_key:
        return jsonify({'error': 'Public key not found.'}), 500
        
    try:
        signature_bytes = bytes.fromhex(signature_hex)
        is_verified = rsa_cipher.verify(message, signature_bytes, public_key)
        
        return jsonify({'is_verified': is_verified}), 200
    except ValueError:
        return jsonify({'is_verified': False, 'message': 'Invalid signature format (must be hex)'}), 200
    except Exception as e:
        return jsonify({'is_verified': False, 'message': f'Verification failed: {str(e)}'}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)