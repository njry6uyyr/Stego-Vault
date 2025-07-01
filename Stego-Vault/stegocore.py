import io, os, struct, zlib, hashlib, secrets, zipfile
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from werkzeug.datastructures import FileStorage

# Derive encryption key from password
def derive_key(password: str, salt: bytes, length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100_000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())

# Encrypt payload
def encrypt(data: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len]) * pad_len
    return salt + iv + encryptor.update(padded_data) + encryptor.finalize()

# Decrypt payload
def decrypt(data: bytes, password: str) -> bytes:
    salt, iv, encrypted = data[:16], data[16:32], data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()
    return padded[:-padded[-1]]

# Embed payload into image using optional randomized LSB
def embed_files_into_image(cover_img_stream: FileStorage, files: list, password: str, anti_detect: bool) -> io.BytesIO:
    image = Image.open(cover_img_stream).convert("RGB")
    if image.format not in ["PNG", "BMP", "TIFF"]:
        # Auto-convert lossy formats like JPEG to lossless PNG
        converted = io.BytesIO()
        image.save(converted, format="PNG")
        converted.seek(0)
        image = Image.open(converted).convert("RGB")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zipf:
        for file in files:
            zipf.writestr(file.filename, file.read())
    zip_data = zip_buffer.getvalue()

    compressed = zlib.compress(zip_data)
    sha = hashlib.sha256(compressed).digest()
    payload = b'STEGOv2' + struct.pack('>I', len(compressed)) + compressed + sha
    encrypted = encrypt(payload, password)
    bits = ''.join(f"{byte:08b}" for byte in encrypted)

    pixels = list(image.getdata())
    if len(bits) > len(pixels) * 3:
        raise ValueError("Image not large enough to hold data.")

    indices = list(range(len(bits)))
    if anti_detect:
        seed = int(hashlib.sha256(password.encode()).hexdigest(), 16)
        rng = secrets.SystemRandom(seed)
        indices = list(range(len(bits)))
        rng.shuffle(indices)

    bit_idx = 0
    new_pixels = []
    for r, g, b in pixels:
        r = (r & ~1) | int(bits[bit_idx]) if bit_idx < len(bits) else r; bit_idx += 1
        g = (g & ~1) | int(bits[bit_idx]) if bit_idx < len(bits) else g; bit_idx += 1
        b = (b & ~1) | int(bits[bit_idx]) if bit_idx < len(bits) else b; bit_idx += 1
        new_pixels.append((r, g, b))

    image.putdata(new_pixels)
    output = io.BytesIO()
    image.save(output, format="PNG")
    output.seek(0)
    return output

# Extract files
def extract_files_from_image(stego_img: FileStorage, password: str) -> io.BytesIO:
    image = Image.open(stego_img).convert("RGB")
    pixels = list(image.getdata())
    bits = ''.join(str(c & 1) for px in pixels for c in px)

    byte_data = bytes([int(bits[i:i+8], 2) for i in range(0, len(bits), 8)])

    try:
        decrypted = decrypt(byte_data, password)
        if not decrypted.startswith(b'STEGOv2'):
            raise ValueError("Incorrect password or corrupted image.")

        length = struct.unpack('>I', decrypted[7:11])[0]
        compressed = decrypted[11:11+length]
        stored_hash = decrypted[11+length:11+length+32]

        if hashlib.sha256(compressed).digest() != stored_hash:
            raise ValueError("Integrity check failed. Wrong password or tampered image.")

        zip_data = zlib.decompress(compressed)
        zip_buf = io.BytesIO(zip_data)
        zip_buf.seek(0)
        return zip_buf

    except Exception as e:
        raise ValueError("Failed to extract data: " + str(e))
