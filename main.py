from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from pathlib import Path
import base64

global private_key
global public_key

# Add the name of the recipients public key here
recipient_public_key = 'magnus.pem'


class Encryption:
    def generate_keypair_if_not_exists():
        if not Path("private.pem").is_file() and not Path("public.pem").is_file():
            keypair = RSA.generate(2048)
            with open("private.pem", 'wb') as f:
                f.write(keypair.export_key('PEM'))
            
            with open("public.pem", 'wb') as f:
                f.write(keypair.public_key().export_key())

    def encrypt_public_key(a_message, public_key):
        encryptor = PKCS1_OAEP.new(public_key)
        encrypted_msg = encryptor.encrypt(a_message)
        return base64.b64encode(encrypted_msg)

    def decrypt_private_key(encoded_encrypted_msg, private_key):
        encryptor = PKCS1_OAEP.new(private_key)
        decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
        decoded_decrypted_msg = encryptor.decrypt(decoded_encrypted_msg)
        return decoded_decrypted_msg

Encryption.generate_keypair_if_not_exists()

with open('private.pem', 'r') as f:
    private_key = RSA.import_key(f.read())

try:
    with open('keys/' + recipient_public_key, 'r') as f:
        public_key = RSA.import_key(f.read())
except Exception:
    print("\nRecipient's public key not found")
    print("-"*32)
    print("Please add the recipients public key in the keys folder")
    print("and update the recipient_public_key variable on line 10\n")
    exit()


def main():
    while True:
        print("\nWelcome to the RSA message encryptor/decryptor")
        print("-"*46, end="\n")
        action = input("Do you want to encrypt (1) or decrypt (2) a message? (1/2): ")

        if action == "1":
            message = input("\nEnter your message: ")
            encrypted_byte = Encryption.encrypt_public_key(bytes(message, 'utf-8'), public_key)
            print("\nEncrypted message: " + encrypted_byte.decode('utf-8'))
            break
        elif action == "2":
            message = input("\nEnter the encrypted hash: ")
            decrypted_byte = Encryption.decrypt_private_key(bytes(message, 'utf-8'), private_key)
            print("\nResult: " + decrypted_byte.decode('utf-8'))
            break
        elif action == "exit":
            print("Goodbye!")
            break
        else:
            print("Invalid command, try again!")


main()