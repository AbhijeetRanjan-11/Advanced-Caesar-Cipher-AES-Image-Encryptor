from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import os
import json
from PIL import Image

UPLOAD_FOLDER = 'static/uploads'

# --- Basic Caesar Cipher ---
def caesar_cipher(text, shift, mode):
    result = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift if mode == "Encrypt" else ord(char) - shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            result += chr(shifted)
        else:
            result += char
    return result

# --- Password Utilities ---
def password_to_key(password, salt=None):
    if salt is None:
        salt = get_random_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return key, salt

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- AES Image File Encryption ---
def encrypt_image_file(image_path, password, mode='CBC'):
    with open(image_path, 'rb') as f:
        file_data = f.read()
    key, salt = password_to_key(password)
    
    if mode == 'CBC':
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
    elif mode == 'GCM':
        cipher = AES.new(key, AES.MODE_GCM)
        encrypted_data, auth_tag = cipher.encrypt_and_digest(file_data)
        iv = cipher.nonce
    else:
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
        iv = None

    enc_path = os.path.splitext(image_path)[0] + "_encrypted.aes"
    with open(enc_path, 'wb') as f:
        f.write(encrypted_data)

    metadata = {
        'salt': salt.hex(),
        'mode': mode,
        'password_hash': hash_password(password),
        'original_extension': os.path.splitext(image_path)[1]
    }
    if mode == 'CBC':
        metadata['iv'] = iv.hex()
    elif mode == 'GCM':
        metadata['nonce'] = iv.hex()
        metadata['auth_tag'] = auth_tag.hex()

    with open(enc_path + '.meta', 'w') as f:
        json.dump(metadata, f)

    return enc_path

def decrypt_image_file(enc_path, password):
    with open(enc_path + '.meta') as f:
        metadata = json.load(f)

    if hash_password(password) != metadata['password_hash']:
        raise ValueError("Incorrect Password")

    with open(enc_path, 'rb') as f:
        encrypted_data = f.read()

    salt = bytes.fromhex(metadata['salt'])
    key, _ = password_to_key(password, salt)
    mode = metadata['mode']

    if mode == 'CBC':
        iv = bytes.fromhex(metadata['iv'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    elif mode == 'GCM':
        nonce = bytes.fromhex(metadata['nonce'])
        auth_tag = bytes.fromhex(metadata['auth_tag'])
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        decrypted_data = cipher.decrypt_and_verify(encrypted_data, auth_tag)
    else:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    dec_path = enc_path.replace("_encrypted.aes", "_decrypted" + metadata['original_extension'])
    with open(dec_path, 'wb') as f:
        f.write(decrypted_data)

    return dec_path

# --- Pixel Scrambling ---
def encrypt_image_pixels(image_path, password):
    img = Image.open(image_path).convert('RGB')
    pixel_bytes = img.tobytes()

    key, salt = password_to_key(password)
    cipher = AES.new(key, AES.MODE_ECB)

    padded_pixels = pad(pixel_bytes, AES.block_size)
    encrypted_pixels = cipher.encrypt(padded_pixels)
    encrypted_pixels = encrypted_pixels[:len(pixel_bytes)]

    encrypted_img = Image.frombytes('RGB', img.size, encrypted_pixels)
    enc_path = os.path.splitext(image_path)[0] + "_pixel_encrypted.png"
    encrypted_img.save(enc_path)

    metadata = {
        'salt': salt.hex(),
        'password_hash': hash_password(password),
        'mode': 'pixel'
    }
    with open(enc_path + '.meta', 'w') as f:
        json.dump(metadata, f)

    return enc_path

def decrypt_image_pixels(enc_path, password):
    with open(enc_path + '.meta') as f:
        metadata = json.load(f)

    if hash_password(password) != metadata['password_hash']:
        raise ValueError("Incorrect Password")

    img = Image.open(enc_path).convert('RGB')
    pixel_bytes = img.tobytes()

    salt = bytes.fromhex(metadata['salt'])
    key, _ = password_to_key(password, salt)
    cipher = AES.new(key, AES.MODE_ECB)

    padded_pixels = pad(pixel_bytes, AES.block_size)
    decrypted_pixels = cipher.decrypt(padded_pixels)
    decrypted_pixels = decrypted_pixels[:len(pixel_bytes)]

    decrypted_img = Image.frombytes('RGB', img.size, decrypted_pixels)
    dec_path = enc_path.replace("_pixel_encrypted.png", "_pixel_decrypted.png")
    decrypted_img.save(dec_path)

    return dec_path
