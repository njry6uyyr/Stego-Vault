# 🕵️‍♂️ StegoVault – Advanced Web-Based Steganography

**StegoVault** is a browser-based steganography tool that allows you to securely **hide multiple files inside images** using advanced encryption and anti-detection techniques. With a retro-themed web interface and modern backend built in Python, it’s designed for **educational**, **ethical hacking**, and **digital forensics** exploration.

> ⚠️ This project is intended for educational purposes **only**. Do not use it for malicious or unauthorized activities.

---

## 🎯 Key Features

- 🔐 **AES-256-CBC encryption** with password-based key derivation (PBKDF2)
- 📦 Hide **multiple files at once** (zipped internally)
- 🎨 Supports **PNG, JPG, BMP, and TIFF** (lossy formats are auto-converted)
- 🧠 Optional **anti-detection mode** with randomized LSB embedding
- 🧪 Includes **integrity verification** using SHA-256 hash
- 💾 Retro-style **web interface** for easy use — no CLI needed
- 🔓 Password-protected extraction system
- 🧰 Built using **Python**, **Flask**, and **Pillow**

---

## 📷 How It Works

StegoVault uses the **Least Significant Bit (LSB)** technique to hide encrypted data inside the color channels (RGB) of an image:

1. Your uploaded files are zipped together.
2. The zip archive is compressed and then encrypted using **AES-256 in CBC mode**.
3. The encrypted data is converted to a binary string.
4. Each bit of the encrypted string is embedded into the **least significant bits** of the image pixels.
5. Optionally, bits are embedded in a **randomized order** (anti-detection mode) based on your password-derived seed.
6. On extraction, the system reverses this process, validating data with a SHA-256 integrity check.

---![Screenshot 2025-07-01 194911](https://github.com/user-attachments/assets/343896ee-5878-418b-a272-83fc33aacbad)


## 🛠 Installation

### ✅ Requirements

- Python 3.8+
- pip

### 📦 Install Dependencies
pip install flask pillow cryptography

Clone the repo and install:
Launch the flask app by:
*cd stegovault*
*python app.py*
