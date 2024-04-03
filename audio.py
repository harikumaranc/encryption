from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import wave

def generate_key_pair(public_key_file, private_key_file):
    key = RSA.generate(2048)
    
    # Save the public key
    with open(public_key_file, 'wb') as public_key_file:
        public_key_file.write(key.publickey().export_key())

    # Save the private key
    with open(private_key_file, 'wb') as private_key_file:
        private_key_file.write(key.export_key())

def load_rsa_key(file_path):
    with open(file_path, 'rb') as key_file:
        key = RSA.import_key(key_file.read())
    return key

def encrypt_audio(input_file, encrypted_output_file, rsa_public_key):
    # Generate a random AES key for symmetric encryption
    aes_key = get_random_bytes(AES.block_size)

    # Create AES cipher object
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)

    with wave.open(input_file, 'rb') as audio_file:
        audio_params = audio_file.getparams()
        audio_data = audio_file.readframes(audio_params.nframes)

    # Pad the data to be a multiple of 16 bytes (block size for AES)
    padded_data = pad(audio_data, AES.block_size)

    # Encrypt the data using AES
    encrypted_data = aes_cipher.encrypt(padded_data)

    # Use RSA public key to encrypt the AES key
    rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    # Write the encrypted data and encrypted AES key to the output file
    with wave.open(encrypted_output_file, 'wb') as encrypted_file:
        encrypted_file.setparams(audio_params)
        encrypted_file.writeframes(encrypted_aes_key + aes_cipher.iv + encrypted_data)

def decrypt_audio(encrypted_input_file, decrypted_output_file, rsa_private_key):
    with wave.open(encrypted_input_file, 'rb') as encrypted_file:
        audio_params = encrypted_file.getparams()
        encrypted_data = encrypted_file.readframes(audio_params.nframes)

    # Extract the encrypted AES key, IV, and data
    rsa_key_size = rsa_private_key.size_in_bytes()
    encrypted_aes_key = encrypted_data[:rsa_key_size]
    iv = encrypted_data[rsa_key_size:rsa_key_size + AES.block_size]
    encrypted_data = encrypted_data[rsa_key_size + AES.block_size:]

    # Use RSA private key to decrypt the AES key
    rsa_cipher = PKCS1_OAEP.new(rsa_private_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)

    # Create AES cipher object
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    # Decrypt the data
    decrypted_data = unpad(aes_cipher.decrypt(encrypted_data), AES.block_size)

    # Write the decrypted data to the output file
    with wave.open(decrypted_output_file, 'wb') as decrypted_file:
        decrypted_file.setparams(audio_params)
        decrypted_file.writeframes(decrypted_data)

# Example usage
input_audio_file = 'drum.wav'
encrypted_audio_file = 'encrypted_audio.wav'
decrypted_audio_file = 'decrypted_audio.wav'
public_key_file = 'public_key.pem'
private_key_file = 'private_key.pem'

# Generate key pair if not already generated
try:
    public_key = load_rsa_key(public_key_file)
    private_key = load_rsa_key(private_key_file)
except FileNotFoundError:
    generate_key_pair(public_key_file, private_key_file)
    public_key = load_rsa_key(public_key_file)
    private_key = load_rsa_key(private_key_file)

# Encrypt the audio using the public key
encrypt_audio(input_audio_file, encrypted_audio_file, public_key)

# Now, you can attempt to play encrypted_audio.wav, but it won't produce meaningful audio.

# Decrypt the audio using the private key
decrypt_audio(encrypted_audio_file, decrypted_audio_file, private_key)

# decrypted_audio.wav should contain the original audio data after decryption, and you can play it without noise.
