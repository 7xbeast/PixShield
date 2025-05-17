# PixShield
PixShield is a user-friendly, image encryption tool designed to protect your visual data from unauthorized access and tampering. 

**Features**

Select image files and preview them before encryption/decryption

Password-based encryption and decryption using AES (CFB mode)

Generate strong random passwords with one click

Toggle password visibility for easy input

Progress bar to show encryption/decryption status

Clear all inputs and reset interface easily

**Installation**

Prerequisites:

Make sure Python 3 is installed on your system.

Install required Python packages:  pip install cryptography pillow

Clone the repository:  git clone https://github.com/7xbeast/PixShield.git

cd PixShield

Run the tool:  python3 pixshield.py

**Usage**

Click Select Image to choose an image file (.jpg, .png, .jpeg, .bmp) or an encrypted file (.enc).

Preview of the selected image will be shown (if applicable).

Enter a password or generate a strong random key using the Generate Key button.

Toggle password visibility with the Show/Hide button.

Click Encrypt to encrypt the image or Decrypt to decrypt the .enc file.

Use the Clear All button to reset the interface and inputs.

Encrypted files will be saved with .enc extension; decrypted images will be saved with _decrypted.jpg suffix.

