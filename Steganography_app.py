import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# AES Encryption
def encrypt_message(message, password):
    backend = default_backend()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return salt + iv + encrypted

# AES Decryption
def decrypt_message(encrypted_data, password):
    backend = default_backend()
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()

# Convert data to binary
def data_to_binary(data):
    return ''.join(format(byte, '08b') for byte in data)

# Convert binary to data
def binary_to_data(binary_str):
    bytes_list = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
    return bytes(int(b, 2) for b in bytes_list)

# Embed data into image
def embed_data(image_path, data, output_path):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    binary_data = data_to_binary(data)
    binary_data += '1111111111111110'  # Delimiter
    data_len = len(binary_data)
    pixels = list(img.getdata())
    new_pixels = []
    data_index = 0
    for pixel in pixels:
        r, g, b = pixel
        if data_index < data_len:
            r = (r & ~1) | int(binary_data[data_index])
            data_index += 1
        if data_index < data_len:
            g = (g & ~1) | int(binary_data[data_index])
            data_index += 1
        if data_index < data_len:
            b = (b & ~1) | int(binary_data[data_index])
            data_index += 1
        new_pixels.append((r, g, b))
    img.putdata(new_pixels)
    img.save(output_path)

# Extract data from image
def extract_data(image_path):
    img = Image.open(image_path)
    pixels = list(img.getdata())
    binary_data = ''
    for pixel in pixels:
        for color in pixel[:3]:
            binary_data += str(color & 1)

    delimiter = '1111111111111110'
    end_index = binary_data.find(delimiter)
    if end_index == -1:
        raise ValueError("Delimiter not found. Data may be corrupted.")
    binary_data = binary_data[:end_index]

    # Ensure byte alignment
    if len(binary_data) % 8 != 0:
        binary_data = binary_data[:-(len(binary_data) % 8)]

    data = binary_to_data(binary_data)

    if len(data) < 32:
        raise ValueError("Extracted data too short to contain valid AES data.")

    return data


# GUI Application
class SteganographyApp:
    def __init__(self, master):
        self.master = master
        master.title("Steganography with AES Encryption")

        # Message Entry
        self.label_message = tk.Label(master, text="Secret Message:")
        self.label_message.pack()
        self.entry_message = tk.Entry(master, width=50)
        self.entry_message.pack()

        # Password Entry
        self.label_password = tk.Label(master, text="Password:")
        self.label_password.pack()
        self.entry_password = tk.Entry(master, show="*", width=50)
        self.entry_password.pack()

        # Buttons
        self.button_embed = tk.Button(master, text="Embed Message", command=self.embed)
        self.button_embed.pack(pady=5)

        self.button_extract = tk.Button(master, text="Extract Message", command=self.extract)
        self.button_extract.pack(pady=5)

    def embed(self):
        message = self.entry_message.get()
        password = self.entry_password.get()
        if not message or not password:
            messagebox.showerror("Error", "Please enter both message and password.")
            return
        image_path = filedialog.askopenfilename(title="Select Image", filetypes=[("PNG Images", "*.png")])
        if not image_path:
            return
        encrypted_message = encrypt_message(message, password)
        output_path = os.path.join(os.path.dirname(image_path), "stego_image.png")
        embed_data(image_path, encrypted_message, output_path)
        messagebox.showinfo("Success", f"Message embedded and saved as {output_path}")

    def extract(self):
        password = self.entry_password.get()
        if not password:
            messagebox.showerror("Error", "Please enter the password.")
            return
        image_path = filedialog.askopenfilename(title="Select Stego Image", filetypes=[("PNG Images", "*.png")])
        if not image_path:
            return
        try:
            encrypted_data = extract_data(image_path)
            decrypted_message = decrypt_message(encrypted_data, password)
            messagebox.showinfo("Extracted Message", decrypted_message)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
