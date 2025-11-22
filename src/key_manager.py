import argparse
import sys
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

# Generate AES key of specified length (default 32 bytes for AES-256), otherwise 16 bytes for AES-128 and 24 bytes for AES-192
def generate_aes_key(length=32):
    return get_random_bytes(length)

# Write AES key to file
def write_aes_key_to_file(key, filepath):
    with open(filepath, 'wb') as f:
        f.write(key)

# Read AES key from file
def read_aes_key_from_file(filepath):
    with open(filepath, 'rb') as f:
        key = f.read()
    return key

# Generate RSA keypair of specified length (default 2038 bits), otherwise 1024 or 4096 bits
def generate_rsa_keypair(length=2048):
    key = RSA.generate(length)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

# Write RSA key (private or public) to file in PEM format
def write_rsa_key_to_file(key, filepath):
    key_pem = key.export_key()
    with open(filepath, 'wb') as f:
        f.write(key_pem) 

# Read RSA key (private or public) from file in PEM format
def read_rsa_key_from_file(filepath):
    with open(filepath, 'rb') as f:
        key = RSA.import_key(f.read())
    return key


def main():
    parser = argparse.ArgumentParser(description='Generate AES or RSA keys')

    parser.add_argument('--type', choices=['aes', 'rsa'], required=True, help='Type of key to generate')
    parser.add_argument('--length', type=int, help='Key length: AES (16/24/32 bytes), RSA (1024/2048/4096 bits)')
    parser.add_argument('--output_file', nargs='+', required=True, help='Path to save the output key(s) file')

    args = parser.parse_args()

    if args.type == 'aes':
        if len(args.output_file) != 1:
            print('AES key requires exactly 1 filepath to save key')
            sys.exit(1)

        if args.length:
            if args.length not in [16, 24, 32]:
                print('AES key length must be 16 or 24 or 32 (bytes)')
                sys.exit(1)
            else:
                key = generate_aes_key(args.length)
        else:
            key = generate_aes_key()
                        
        write_aes_key_to_file(key, args.output_file[0])


    if args.type == 'rsa':
        private_filepath = None
        public_filepath = None

        if len(args.output_file) != 2:
            print('RSA keys require exactly 2 filepath to save keys')
            sys.exit(1)

        for path in args.output_file:
            if path.endswith('.key'):
                private_filepath = path
            elif path.endswith('.pub'):
                public_filepath = path
        
        if not private_filepath or not public_filepath:
            print('RSA requires one .key (private) and one .pub (public) filepath')
            sys.exit(1)

        if args.length:
            if args.length not in [1024, 2048, 4096]:
                print('RSA key length must be 1024, 2048 or 4096 (bits)')
                sys.exit(1)
            else:
                private_key, public_key = generate_rsa_keypair(args.length)
        else:
            private_key, public_key = generate_rsa_keypair()

        write_rsa_key_to_file(private_key, private_filepath)
        write_rsa_key_to_file(public_key, public_filepath)   



if __name__ == '__main__':
    main()