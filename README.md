# hybrid-cryptosystem

## Installation
- Navigate to the `src` directory
```bash
cd src
```

- To install the required dependencies, run the following command:
```bash
pip install pycryptodome
pip install argparse
```

## Running the Code
### 1. Generate key
- Run the `key_manager.py` to generate RSA keys or AES key.

#### To generate RSA key pairs, use the following command
```bash
python key_manager.py --type rsa --output_file <public_key_file> <private_key_file> --length <key_length>
```
- `--type`: Type of key to generate (`rsa`) - ***required***
- `--output_file`: Output file for public and private keys - ***required*** exactly 2 arguments with .pub and .key extensions
- `--length`: Length of the RSA key in bits (1024, 2048, 4096) - ***optional*** with default value 2048


#### To generate AES key, use the following command
```bash
python key_manager.py --type aes --output_file <key_file> --length <key_length>
```
- `--type`: Type of key to generate (`aes`) - ***required***
- `--output_file`: Output file for AES key - ***required*** exactly 1 argument with .key extension
- `--length`: Length of the AES key in bytes (16, 24, 32) - ***optional*** with default value 32

### 2. Encrypt file
- To encrypt a file, run the `encryptor.py` with the following command:
```bash 
python encryptor.py --receiver_pub_key <receiver_public_key_file>
                    --sender_priv_key <sender_private_key_file>
                    --input_file <input_file_to_encrypt>
                    --output_encrypted_file <output_encrypted_file>
                    --output_encrypted_key <output_encrypted_session_key_file>
                    --output_signature <output_signature_file>
```
- `--receiver_pub_key`: Receiver's public key file - ***required*** with .pub extension
- `--sender_priv_key`: Sender's private key file - ***required*** with .key extension
- `--input_file`: Input file to encrypt - ***required***
- `--output_encrypted_file`: Output file for encrypted data - ***required***
- `--output_encrypted_key`: Output file for encrypted session key - ***required***
- `--output_signature`: Output file for digital signature - ***required***


### 3. Decrypt file
- To decrypt a file, run the `decryptor.py` with the following command:
```bash 
python decryptor.py --receiver_priv_key <receiver_private_key_file>
                    --sender_pub_key <sender_public_key_file>
                    --input_encrypted_key <input_encrypted_session_key_file>
                    --input_file <input_file_to_decrypt>
                    --input_signature <input_signature_file>
                    --output_decrypted_file <output_decrypted_file>
```
- `--receiver_priv_key`: Receiver's private key file - ***required*** with .key extension
- `--sender_pub_key`: Sender's public key file - ***required*** with .pub extension
- `--input_encrypted_key`: Input file for encrypted session key - ***required***
- `--input_file`: Input file to decrypt - ***required***
- `--input_signature`: Input file for digital signature to verify - ***required***
- `--output_decrypted_file`: Output file for decrypted data - ***required***

## Example Usage
### 1. Generate 2 RSA key pairs for sender and receiver with default length 2038 bits
```bash
python key_manager.py --type rsa --output_file priv1.key pub1.pub
python key_manager.py --type rsa --output_file priv2.key pub2.pub
```

### 2. Encrypt a file `test.txt` using receiver's public key `pub2.pub` and sign the hash using sender's private key `priv1.key`
```bash
python encryptor.py --receiver_pub_key pub2.pub
                    --sender_priv_key priv1.key
                    --input_file test.txt
                    --output_encrypted_file encrypted_test.enc
                    --output_encrypted_key encrypted_key.key
                    --output_signature sig1.sig
```

### 3. Decrypt the file `encrypted_test.enc` using receiver's private key `priv2.key` and verify the signature using sender's public key `pub1.pub`
```bash
python decryptor.py --receiver_priv_key priv2.key
                    --sender_pub_key pub1.pub
                    --input_encrypted_key encrypted_key.key
                    --input_file encrypted_test.enc
                    --input_signature sig1.sig
                    --output_decrypted_file decrypted_test.txt
```