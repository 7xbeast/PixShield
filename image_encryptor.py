
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import secrets
import string
import random
import threading

# Key derivation
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt function
def encrypt_file(file_path, password, progress_callback=None):
    with open(file_path, "rb") as f:
        data = f.read()
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    encrypted_blob = salt + iv + encrypted_data
    output_path = file_path + ".enc"
    with open(output_path, "wb") as f:
        f.write(encrypted_blob)
    if progress_callback:
        progress_callback(100)

# Decrypt function
def decrypt_file(file_path, password, progress_callback=None):
    with open(file_path, "rb") as f:
        blob = f.read()
    salt = blob[:16]
    iv = blob[16:32]
    encrypted_data = blob[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    output_path = file_path.replace(".enc", "_decrypted.jpg")
    with open(output_path, "wb") as f:
        f.write(decrypted_data)
    if progress_callback:
        progress_callback(100)

def encrypt_action():
    if not selected_file:
        messagebox.showwarning("Warning", "Select an image first!")
        return
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Warning", "Enter a password!")
        return
    threading.Thread(target=run_encrypt, args=(selected_file, password), daemon=True).start()

def decrypt_action():
    if not selected_file:
        messagebox.showwarning("Warning", "Select an encrypted file first!")
        return
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Warning", "Enter a password!")
        return
    threading.Thread(target=run_decrypt, args=(selected_file, password), daemon=True).start()

def run_encrypt(file_path, password):
    progress_var.set(0)
    encrypt_file(file_path, password, lambda val: progress_var.set(val))
    messagebox.showinfo("Success", f"Image encrypted and saved as {file_path}.enc")

def run_decrypt(file_path, password):
    progress_var.set(0)
    try:
        decrypt_file(file_path, password, lambda val: progress_var.set(val))
        messagebox.showinfo("Success", "Image decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def select_file():
    global selected_file
    file_path = filedialog.askopenfilename(
        title="Select Image or Encrypted File",
        filetypes=[("All Supported", "*.jpg *.png *.jpeg *.bmp *.enc")]
    )
    if file_path:
        selected_file = file_path
        selected_file_label.config(text=os.path.basename(file_path))
        show_image_preview(file_path)
        if file_path.lower().endswith(".enc"):
            decrypt_btn.config(state=NORMAL)
        else:
            decrypt_btn.config(state=DISABLED)

def generate_random_password():
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(chars) for _ in range(12))
    password_entry.delete(0, END)
    password_entry.insert(0, password)
    root.clipboard_clear()
    root.clipboard_append(password)
    decrypt_btn.config(state=DISABLED)
    password_entry.focus_set()

def show_image_preview(path):
    try:
        img = Image.open(path)
        img.thumbnail((120, 120))
        img_tk = ImageTk.PhotoImage(img)
        preview_label.config(image=img_tk, text="")
        preview_label.image = img_tk
    except Exception:
        preview_label.config(image='', text="No Preview")

def toggle_password_visibility():
    if password_entry.cget('show') == '*':
        password_entry.config(show='')
        toggle_button.config(text='Hide')
    else:
        password_entry.config(show='*')
        toggle_button.config(text='Show')
    password_entry.focus_set()

def clear_all():
    global selected_file
    selected_file = None
    selected_file_label.config(text="No file selected")
    password_entry.delete(0, END)
    preview_label.config(image='', text="No Preview")
    preview_label.image = None
    progress_var.set(0)
    decrypt_btn.config(state=NORMAL)
    if password_entry.cget('show') == '':
        toggle_password_visibility()

# GUI setup
selected_file = None
root = tb.Window(themename="darkly")
root.title("🔐 Secure Image Encryptor")
root.geometry("550x580")

default_font = ('Segoe UI', 10)
root.option_add("*Font", default_font)

# File selection
file_frame = tb.LabelFrame(root, text="Select File", bootstyle="secondary")
file_frame.pack(padx=10, pady=10, fill="x")
tb.Button(file_frame, text="📂 Select Image", bootstyle="info-outline", command=select_file).pack(pady=5)
selected_file_label = tb.Label(file_frame, text="No file selected")
selected_file_label.pack(pady=2)

# Image preview
preview_frame = tb.Frame(root, bootstyle="dark")
preview_frame.pack(pady=10)
preview_label = tb.Label(preview_frame, text="No Preview", bootstyle="dark")
preview_label.pack(padx=10, pady=10)

# Password frame
password_frame = tb.LabelFrame(root, text="Enter Key", bootstyle="secondary")
password_frame.pack(padx=10, pady=10, fill="x")
frame_pw = tb.Frame(password_frame)
frame_pw.pack(pady=5)
tb.Label(frame_pw, text="🔑 Password:").pack(side="left", padx=5)
password_entry = tb.Entry(frame_pw, width=25, show="*")
password_entry.pack(side="left", padx=5)
toggle_button = tb.Button(frame_pw, text="Show", bootstyle="warning-outline", command=toggle_password_visibility)
toggle_button.pack(side="left", padx=5)
tb.Button(frame_pw, text="🎲 Generate Key", bootstyle="success-outline", command=generate_random_password).pack(side="left", padx=5)

# Progress bar
progress_var = tb.IntVar()
progress_bar = tb.Progressbar(root, orient="horizontal", length=400, mode="determinate", variable=progress_var, bootstyle="success-striped")
progress_bar.pack(pady=20)

# Encrypt/Decrypt
action_frame = tb.LabelFrame(root, text="Actions", bootstyle="secondary")
action_frame.pack(padx=10, pady=10)
tb.Button(action_frame, text="🛡️ Encrypt", bootstyle="success", command=encrypt_action).pack(side="left", padx=20, pady=5)
decrypt_btn = tb.Button(action_frame, text="🔓 Decrypt", bootstyle="danger", command=decrypt_action)
decrypt_btn.pack(side="left", padx=20, pady=5)
decrypt_btn.config(state=DISABLED)

# Clear all
tb.Button(root, text="♻️ Clear All", bootstyle="warning", command=clear_all).pack(pady=15)

root.mainloop()
