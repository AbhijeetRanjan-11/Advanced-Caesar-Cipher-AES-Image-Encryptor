🔐 Advanced Caesar Cipher + AES Image Encryptor

Secure your text and images with modern cryptography, pixel-level scrambling, and a clean Python GUI interface.

📦 Project Overview

This project combines classic encryption with modern AES security and pixel-level image scrambling:

✅ Caesar Cipher — Encrypt & Decrypt text with customizable shift
✅ AES Image Encryption — Secure full image files using AES (CBC, GCM, ECB modes)
✅ Pixel Scrambling — Visual scrambling of image pixels with AES for obfuscation
✅ Password Protection — PBKDF2-based key derivation with SHA-256 password hashing
✅ User-Friendly GUI — Tkinter-based graphical interface with image previews

✨ Features

    🔒 Caesar Cipher Text Encryption & Decryption

    🖼️ AES File Encryption with CBC, GCM, ECB modes

    🎨 Pixel-level scrambling for image obfuscation

    🔑 Secure password-based AES key generation

    📂 Metadata handling for decryption (IV, salt, hash)

    🖥️ GUI image previews for Original, Encrypted, and Decrypted images

    ⚡ Supports .jpg, .png, .bmp, .tiff formats

🛠️ Technologies

    Python 3

    Tkinter (GUI)

    Pillow (PIL) for image handling

    PyCryptodome for AES encryption & hashing


🛠️ Languages & Technologies Used

✅ Python 3 — Core programming language for application logic

✅ Tkinter — Python's built-in GUI framework for desktop interface

✅ Pillow (PIL) — Image handling and processing

✅ PyCryptodome — Cryptography library for AES encryption, decryption, and secure hashing

✅ HTML (Planned for web version) — For creating responsive web pages in the Flask version

✅ CSS (Planned for web version) — Styling web pages, Bootstrap integration planned

✅ Breakdown by Area:

Area	Language / Tool
Core Logic	Python
GUI Desktop App	Tkinter
Image Processing	Pillow (PIL)
Encryption / Hashing	PyCryptodome (AES, SHA-256)
Password Derivation	PBKDF2 (via hashlib)
Planned Web Version	Python (Flask), HTML, CSS (Bootstrap)


🚀 How to Run
1. Install Dependencies

pip install -r requirements.txt

2. Launch the Application

python app.py

3. Use the GUI to:

✔ Encrypt & Decrypt text using Caesar Cipher
✔ Encrypt images as files using AES (with CBC, GCM, or ECB)
✔ Scramble image pixels for visual encryption
✔ Decrypt image files or unscramble pixels
📂 Project Structure

├── app.py                # Main application with GUI logic
├── encryption_utils.py   # Encryption & decryption helper functions
├── requirements.txt      # Project dependencies
├── static/
│   └── uploads/          # Stores encrypted and decrypted images
└── templates/            # For future web version

🔒 Security Recommendations

    Use AES CBC or GCM modes for strong encryption

    ECB pixel scrambling provides basic obfuscation, not cryptographically secure for sensitive data

    Password hashes and metadata securely stored alongside encrypted files

🌐 Upcoming Features

    Flask web version with browser-based encryption

    Downloadable encrypted files from the web interface

    Responsive Bootstrap-powered UI

    Additional file format support

🎯 Ideal For

✔ Cybersecurity students
✔ Cryptography demonstrations
✔ Secure image handling projects
✔ Educational encryption tools

📢 Contributing

Pull requests are welcome. For major changes, please open an issue to discuss your ideas.
📄 License

MIT License — free for personal and educational use.

🎯 Summary:

✔ 100% Python project for desktop
✔ GUI with Tkinter
✔ Cryptography using AES + SHA-256
✔ Planned HTML/CSS for future web-based encryption
