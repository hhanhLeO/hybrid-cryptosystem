import argparse
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from key_manager import generate_aes_key, read_rsa_key_from_file

def parse_arguments():
    parser = argparse.ArgumentParser(description='Hybrid Encryptor')

    parser.add_argument('--receiver_pub_key', type=str, required=True, help='Path to the receiver\'s RSA public key file')
    parser.add_argument('--sender_priv_key', type=str, required=True, help='Path to the sender\'s RSA private key file')
    parser.add_argument('--input_file', type=str, required=True, help='Path to the input file to be encrypted')
    parser.add_argument('--output_encrypted_file', type=str, required=True, help='Path to save the encrypted output file')
    parser.add_argument('--output_encrypted_key', type=str, required=True, help='Path to save the encrypted symmetric key file')
    parser.add_argument('--output_signature', type=str, required=True, help='Path to save the signature file')

    return parser.parse_args()

# Build data to be encrypted, includes header (extension length + extension) + file data
def build_data(file_name, file_data):
    last_dot_position = file_name.rfind('.')
    extension = ''
    if last_dot_position != -1:
        extension = file_name[last_dot_position:]
    header = len(extension).to_bytes(1, 'big') + extension.encode()
    return header + file_data

# Encrypt data using AES GCM
def encrypt_file_data(session_key, file_data):
    nonce = get_random_bytes(12)
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    return nonce, tag, ciphertext

# Encrypt session key (symmetric key) using RSA public key
def encrypt_session_key(session_key, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_session_key = cipher.encrypt(session_key)
    return encrypted_session_key

# Write encrypted data to file (none + tag + ciphertext)
def write_encrypted_data_to_file(nonce, tag, ciphertext, filepath):
    with open(filepath, 'wb') as f:
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)

# Sign the hash of the plaintext data
def create_signature(plaintext, private_key):
    hashed_data = SHA256.new(plaintext)
    signature = pkcs1_15.new(private_key).sign(hashed_data)
    return signature



if __name__ == '__main__':
    args = parse_arguments()

    # Read recevier's public key from file
    receiver_pub_key = read_rsa_key_from_file(args.receiver_pub_key)

    # Read sender's private key from file
    sender_priv_key = read_rsa_key_from_file(args.sender_priv_key)

    # Read file's data
    with open(args.input_file, 'rb') as f:
        file_data = f.read()

    # Create header
    data = build_data(args.input_file, file_data)

    # Generate AES key and encrypt file data, session key = symmetric key
    session_key = generate_aes_key()
    nonce, tag, ciphertext = encrypt_file_data(session_key, data)

    # Write encrypted data to file with .enc extension
    output_filename = args.output_encrypted_file
    write_encrypted_data_to_file(nonce, tag, ciphertext, output_filename)

    # Encrypt session key
    encrypted_session_key = encrypt_session_key(session_key, receiver_pub_key)

    with open(args.output_encrypted_key, 'wb') as f:
        f.write(encrypted_session_key)  

    # Create signature
    signature = create_signature(file_data, sender_priv_key)
    with open(args.output_signature, 'wb') as f:
        f.write(signature)
