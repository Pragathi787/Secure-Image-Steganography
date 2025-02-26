# Secure-Image-Steganography
This project enhances data security by encrypting messages using Elliptic Curve Diffie-Hellman (ECDH) key exchange and AES-256 encryption, then embedding them into images using Least Significant Bit (LSB) steganography. The hidden message remains undetectable, ensuring secure and private communication.

Features

ECDH for Secure Key Exchange – Prevents eavesdropping attacks.
AES-256 Encryption – Protects hidden messages from unauthorized access.
LSB Steganography – Embeds encrypted messages into images without visual distortion.
SSIM & PSNR Image Analysis – Verifies image quality after encoding.
Automated Key Handling – Keys are securely stored in text files for easy access.

Encoding a Message
Choose Option 1 (Encode a message).
Provide the image path and message to be hidden.
The stego image is generated, and keys are saved automatically.
Decoding a Message
Choose Option 2 (Decode a message).
Provide the stego image path.
The encrypted message is extracted & decrypted using stored keys.

The project analyzes image integrity after steganography using:
SSIM (Structural Similarity Index) – Measures how similar the original & stego images are.
PSNR (Peak Signal-to-Noise Ratio) – Evaluates quality loss in dB.
Example Output:
SSIM Score: 99.95%
PSNR Value: 49.5 dB

