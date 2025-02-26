import cv2
import numpy as np
import os
import matplotlib.pyplot as plt
from skimage.metrics import structural_similarity as ssim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from ECDHKeyExchange import generate_keys, derive_shared_key
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def generate_unique_filename(base_name="stego_image", extension=".png"):
    counter = 1
    while os.path.exists(f"{base_name}_{counter}{extension}"):
        counter += 1
    return f"{base_name}_{counter}{extension}"

def encrypt_message(message, shared_key):
    """Encrypts a message using AES-256 with a derived shared key."""
    iv = os.urandom(16)
    cipher = AES.new(shared_key, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted_bytes).decode()

def decrypt_message(encrypted_message, shared_key):
    """Decrypts an AES-256 encrypted message using a derived shared key."""
    encrypted_data = base64.b64decode(encrypted_message)
    iv = encrypted_data[:16]
    encrypted_bytes = encrypted_data[16:]
    cipher = AES.new(shared_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_bytes), AES.block_size).decode()


def encode_image(image_path, message, output_path=None):
    """Hides an AES-encrypted message inside an image using LSB steganography."""
    sender_private_key, sender_public_key, recipient_private_key, recipient_public_key = generate_keys()
    shared_key = derive_shared_key(sender_private_key, recipient_public_key)  # ✅ Correct



    encrypted_message = encrypt_message(message, shared_key)# Encrypt the message using ECDH-derived key
    binary_message = ''.join(format(ord(char), '08b') for char in encrypted_message) + '111111111111111011111111'  # EOF marker

    image = cv2.imread(image_path)
    if image is None:
        print("Error: Could not open the image. Check the path.")
        return

    data_index = 0
    for row in image:
        for pixel in row:
            for channel in range(3):
                if data_index < len(binary_message):
                    pixel[channel] = (pixel[channel] & ~1) | int(binary_message[data_index])  # Hide bits
                    data_index += 1
                else:
                    break

    if output_path is None:
        output_path = generate_unique_filename()

    cv2.imwrite(output_path, image)
    print(f"Encrypted message successfully hidden in {output_path}")

    # Save Recipient's Private Key
    with open("recipient_private_key.txt", "w") as f:
         f.write(recipient_private_key.private_bytes(
             encoding=serialization.Encoding.PEM,
             format=serialization.PrivateFormat.PKCS8,
             encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8'))

    # Save Sender's Public Key
    with open("sender_public_key.txt", "w") as f:
         f.write(base64.b64encode(sender_public_key.public_bytes(
             encoding=serialization.Encoding.X962,
             format=serialization.PublicFormat.UncompressedPoint
        )).decode('utf-8'))
    return sender_private_key, sender_public_key


def decode_image(image_path, recipient_private_key, sender_public_key):
    """Extracts an AES-encrypted message from an image and decrypts it."""
    image = cv2.imread(image_path)
    if image is None:
        print("Error: Could not open the image. Check the path.")
        return

    binary_message = ""
    for row in image:
        for pixel in row:
            for channel in range(3):
                binary_message += str(pixel[channel] & 1)

    message_bits = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
    message = ""

    for i in range(len(message_bits)):
        if ''.join(message_bits[i:i+3]) == '111111111111111011111111':  # EOF marker
            break
        message += chr(int(message_bits[i], 2))

    try:
        shared_key = derive_shared_key(recipient_private_key, sender_public_key)
        decrypted_message = decrypt_message(message.strip('\x00'), shared_key)  # Decrypt the extracted message
        print("Decoded and Decrypted Message:", decrypted_message)
    except:
        print("Error: Could not decrypt the message. Ensure the correct keys are used.")

def compare_images(original_path, stego_path):
    original = cv2.imread(original_path, cv2.IMREAD_GRAYSCALE)
    stego = cv2.imread(stego_path, cv2.IMREAD_GRAYSCALE)

    if original is None or stego is None:
        print("Error: Could not open one of the images. Check the file paths.")
        return

    ssim_score = ssim(original, stego) * 100
    mse = np.mean((original - stego) ** 2)
    psnr = 10 * np.log10(255**2 / mse) if mse != 0 else float('inf')

    print(f"SSIM Score: {ssim_score:.6f}%")
    print(f"PSNR Value: {psnr:.2f} dB")

    plt.figure(figsize=(6, 4))
    plt.bar(["SSIM (%)", "PSNR (dB)"], [ssim_score, psnr], color=['blue', 'green'])
    plt.ylim(0, 110)  # Adjusted scale for better differentiation
    plt.ylabel("Score")

    if ssim_score > 99.9:
        conclusion = "The image has undergone minimal modification, ensuring high fidelity."
    elif ssim_score > 99.0:
        conclusion = "The image has very slight modifications but remains visually unchanged."
    else:
        conclusion = "Some noticeable modifications have occurred, but the image still retains high similarity."

    plt.title("Image Similarity Analysis")
    plt.text(0.5, -0.15, conclusion, ha='center', va='top', fontsize=12, color='black', bbox=dict(facecolor='white', edgecolor='black', boxstyle='round,pad=0.5'), transform=plt.gca().transAxes)

    plt.tight_layout()
    plt.show()

def main():
    while True:
        choice = input("Choose an option: \n1. Encode a message\n2. Decode a message\n3. Compare images\n4. Exit\nEnter your choice: ")

        if choice == "1":
            image_path = input("Enter the absolute path of the image to hide the message in: ")
            message = input("Enter the message you want to hide: ")
            sender_private_key, sender_public_key = encode_image(image_path, message)
            print("Sender's Public Key:", sender_public_key)

        elif choice == "2":
            image_path = input("Enter the absolute path of the stego image to decode: ")
            # Read Recipient's Private Key from File
            with open("recipient_private_key.txt", "rb") as f:
                 recipient_private_key = serialization.load_pem_private_key(
                     f.read(),
                     password=None,
                     backend=None
                 )
            # Read Sender's Public Key from File (Convert back to key object)
            with open("sender_public_key.txt", "r") as f:
                 sender_public_key_bytes = base64.b64decode(f.read().strip())
                 sender_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), sender_public_key_bytes)

             # Call decode function with properly loaded keys
            decode_image(image_path, recipient_private_key, sender_public_key)

        elif choice == "3":
            original_path = input("Enter the path of the original image: ")
            stego_path = input("Enter the path of the stego image: ")
            compare_images(original_path, stego_path)

        elif choice == "4":
            print("Exiting program.")
            break

        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()
