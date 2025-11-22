import argparse
import sys
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from key_manager import read_rsa_key_from_file

def parse_arguments():
    parser = argparse.ArgumentParser(description='Hybrid Encryptor')

    parser.add_argument('--receiver_priv_key', type=str, required=True, help='Path to the receiver\'s RSA private key file')
    parser.add_argument('--sender_pub_key', type=str, required=True, help='Path to the sender\'s RSA public key file')
    parser.add_argument('--input_encrypted_key', type=str, required=True, help='Path to the encrypted symmetric key file')
    parser.add_argument('--input_file', type=str, required=True, help='Path to the input file to be decrypted')
    parser.add_argument('--input_signature', type=str, required=True, help='Path to the input signature file')
    parser.add_argument('--output_decrypted_file', type=str, required=True, help='Path to save the decrypted output file')

    return parser.parse_args()

# Parse decrypted data to extract extension and file data
def parse_data(decryptedtext):
    extension_length = int.from_bytes(decryptedtext[:1], 'big')
    extension = ''
    if extension_length > 0:
        extension = decryptedtext[1:extension_length + 1].decode()
    
    file_data = decryptedtext[1 + extension_length:]
    return extension, file_data

# Decrypt data using AES GCM
def decrypt_file_data(session_key, nonce, tag, ciphertext):
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# Decrypt session key (symmetric key) using RSA private key
def decrypt_session_key(encrypted_session_key, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    session_key = cipher.decrypt(encrypted_session_key)
    return session_key

# Read encrypted data from file (nonce + tag + ciphertext)
def read_encrypted_data_from_file(filepath):
    with open(filepath, 'rb') as f:
        nonce = f.read(12)
        tag = f.read(16)
        ciphertext = f.read()
    return nonce, tag, ciphertext

# Verify the signature
def verify_signature(plaintext, signature, public_key):
    hashed_data = SHA256.new(plaintext)
    try:
        pkcs1_15.new(public_key).verify(hashed_data, signature)
        return True
    except (ValueError, TypeError):
        return False
    


if __name__ == '__main__':
    args = parse_arguments()

    # Read recevier's private key from file
    receiver_priv_key = read_rsa_key_from_file(args.receiver_priv_key)

    # Read sender's public key from file
    sender_pub_key = read_rsa_key_from_file(args.sender_pub_key)

    # Read encrypted session key
    with open(args.input_encrypted_key, 'rb') as f:
        encrypted_session_key = f.read()

    # Decrypt session key
    session_key = decrypt_session_key(encrypted_session_key, receiver_priv_key)

    # Read encrypted data from file
    nonce, tag, ciphertext = read_encrypted_data_from_file(args.input_file)
    
    decrypted_data = decrypt_file_data(session_key, nonce, tag, ciphertext)

    # Parse data 
    extension, file_data = parse_data(decrypted_data)

    # Verify signature
    with open(args.input_signature, 'rb') as f:
        signature = f.read()
    
    is_valid = verify_signature(file_data, signature, sender_pub_key)

    if is_valid:
        print('FILE IS VALID')
    else:
        print('FILE IS INVALID')
        sys.exit(1)

    # Write decrypted file data to output file
    output_filename = args.output_decrypted_file + extension
    with open(output_filename, 'wb') as f:
        f.write(file_data)