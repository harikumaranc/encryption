from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import wave
import os

app = Flask(__name__)

def generate_key_pair(public_key_file, private_key_file):
    key = RSA.generate(2048)

    with open(public_key_file, 'wb') as public_key_file:
        public_key_file.write(key.publickey().export_key())

    with open(private_key_file, 'wb') as private_key_file:
        private_key_file.write(key.export_key())

def load_rsa_key(file_path):
    with open(file_path, 'rb') as key_file:
        key = RSA.import_key(key_file.read())
    return key

def encrypt_audio(input_file, encrypted_output_file, rsa_public_key):
    aes_key = get_random_bytes(AES.block_size)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)

    with wave.open(input_file, 'rb') as audio_file:
        audio_params = audio_file.getparams()
        audio_data = audio_file.readframes(audio_params.nframes)

    padded_data = pad(audio_data, AES.block_size)
    encrypted_data = aes_cipher.encrypt(padded_data)

    rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    static_folder = os.path.join(os.getcwd(), 'static')
    os.makedirs(static_folder, exist_ok=True)

    encrypted_audio_file_path = os.path.join(static_folder, encrypted_output_file)
    with wave.open(encrypted_audio_file_path, 'wb') as encrypted_file:
        encrypted_file.setparams(audio_params)
        encrypted_file.writeframes(encrypted_aes_key + aes_cipher.iv + encrypted_data)

    return encrypted_audio_file_path

def decrypt_audio(encrypted_input_file, decrypted_output_file, rsa_private_key):
    try:
        with wave.open(encrypted_input_file, 'rb') as encrypted_file:
            audio_params = encrypted_file.getparams()
            encrypted_data = encrypted_file.readframes(audio_params.nframes)
    except Exception as e:
        print(f"Error reading encrypted audio file: {str(e)}")
        return None

    rsa_key_size = rsa_private_key.size_in_bytes()

    if len(encrypted_data) <= rsa_key_size + AES.block_size:
        print("Error: Insufficient data for decryption.")
        return None

    encrypted_aes_key = encrypted_data[:rsa_key_size]
    iv = encrypted_data[rsa_key_size:rsa_key_size + AES.block_size]
    encrypted_data = encrypted_data[rsa_key_size + AES.block_size:]

    try:
        rsa_cipher = PKCS1_OAEP.new(rsa_private_key)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)
    except Exception as e:
        print(f"Error decrypting AES key: {str(e)}")
        return None

    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(aes_cipher.decrypt(encrypted_data), AES.block_size)

    try:
        with wave.open(decrypted_output_file, 'wb') as decrypted_file:
            decrypted_file.setparams(audio_params)
            decrypted_file.writeframes(decrypted_data)
    except Exception as e:
        print(f"Error writing decrypted audio file: {str(e)}")
        return None

    return decrypted_output_file

@app.route('/')
def index_page():
    return render_template('index.html')

@app.route('/encrypt')
def encrypt_page():
    return render_template('encrypt.html')

@app.route('/decrypt')
def decrypt_page():
    return render_template('decrypt.html')

@app.route('/encrypt_audio', methods=['POST'])
def encrypt_audio_route():
    try:
        audio_file = request.files['audioFile']
        public_key = load_rsa_key('public_key.pem')

        encrypted_audio_file = encrypt_audio(audio_file, 'encrypted_audio.wav', public_key)

        return jsonify({'url': f'/static/{os.path.basename(encrypted_audio_file)}'})
    except Exception as e:
        print(f"Error encrypting audio: {str(e)}")
        return jsonify({'error': 'Encryption failed'}), 500

@app.route('/decrypt_audio', methods=['POST'])
def decrypt_audio_route():
    try:
        encrypted_audio_file = request.files['encryptedAudioFile']
        private_key_file = request.files['privateKeyFile']

        encrypted_audio_path = os.path.join('static', 'uploaded_encrypted_audio.wav')
        encrypted_audio_file.save(encrypted_audio_path)

        private_key_data = private_key_file.read()
        private_key = RSA.import_key(private_key_data)
        public_key = load_rsa_key('public_key.pem')

        if private_key.publickey().export_key() == public_key.export_key():
            decrypted_audio_file = decrypt_audio(encrypted_audio_path, 'static/decrypted_audio.wav', private_key)

            if decrypted_audio_file:
                return jsonify({'url': f'/static/{os.path.basename(decrypted_audio_file)}'})
            else:
                return jsonify({'error': 'Decryption failed'}), 500
        else:
            return jsonify({'error': 'Mismatched public key'}), 400

    except Exception as e:
        print(f"Error decrypting audio: {str(e)}")
        return jsonify({'error': 'Decryption failed'}), 500

@app.route('/download_private_key')
def download_private_key():
    private_key_path = 'private_key.pem'
    return send_file(private_key_path, as_attachment=True)

@app.route('/download_encrypted_audio')
def download_encrypted_audio():
    encrypted_audio_path = 'static/encrypted_audio.wav'
    return send_file(encrypted_audio_path, as_attachment=True)

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

if __name__ == '__main__':
    if not os.path.exists('public_key.pem') or not os.path.exists('private_key.pem'):
        generate_key_pair('public_key.pem', 'private_key.pem')

    app.run(debug=True)
