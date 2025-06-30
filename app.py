from flask import Flask, render_template, request, send_from_directory
import os
from encryption_utils import (
    caesar_cipher, encrypt_image_file, encrypt_image_pixels,
    decrypt_image_file, decrypt_image_pixels, UPLOAD_FOLDER
)

app = Flask(__name__)

# Uploads directory configuration
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensures uploads folder exists

# Home page
@app.route('/')
def index():
    return render_template('index.html')

# Caesar Cipher Encryption/Decryption
@app.route('/caesar', methods=['POST'])
def caesar():
    text = request.form['text']
    shift = int(request.form['shift'])
    mode = request.form['mode']
    result = caesar_cipher(text, shift, mode)
    return render_template('result.html', result=result, task="Caesar Cipher")

# AES File-based Image Encryption
@app.route('/encrypt_image', methods=['POST'])
def encrypt_image():
    file = request.files['image']
    password = request.form['password']
    mode = request.form['aes_mode']
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(image_path)
    enc_path = encrypt_image_file(image_path, password, mode)
    return render_template('result.html', result=f"<a href='/uploads/{os.path.basename(enc_path)}'>Download Encrypted File</a>", task="AES File Encryption")

# Pixel-Level Image Encryption
@app.route('/encrypt_pixels', methods=['POST'])
def encrypt_pixels():
    file = request.files['image']
    password = request.form['password']
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(image_path)
    enc_path = encrypt_image_pixels(image_path, password)
    return render_template('result.html', result=f"<a href='/uploads/{os.path.basename(enc_path)}'>Download Pixel-Encrypted Image</a>", task="Pixel Scrambling")

# AES File-based Image Decryption
@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    file = request.files['file']
    password = request.form['password']
    enc_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(enc_path)
    try:
        dec_path = decrypt_image_file(enc_path, password)
        return render_template('result.html', result=f"<a href='/uploads/{os.path.basename(dec_path)}'>Download Decrypted Image</a>", task="AES File Decryption")
    except Exception as e:
        return str(e), 400

# Pixel-Level Image Decryption
@app.route('/decrypt_pixels', methods=['POST'])
def decrypt_pixels():
    file = request.files['image']
    password = request.form['password']
    enc_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(enc_path)
    try:
        dec_path = decrypt_image_pixels(enc_path, password)
        return render_template('result.html', result=f"<a href='/uploads/{os.path.basename(dec_path)}'>Download Decrypted Image</a>", task="Pixel Decryption")
    except Exception as e:
        return str(e), 400

# Serve Uploaded Files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Run the Flask App
if __name__ == '__main__':
    app.run(debug=True)
