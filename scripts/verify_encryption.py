from src.logging.encryption import encrypt, decrypt

def main():
    sample = b"Hello from staging encryption test"
    keyid, ciphertext = encrypt(sample)
    print("Encrypted with key:", keyid)
    try:
        pt = decrypt(ciphertext)
        print("Decrypted text:", pt.decode('utf-8'))
    except Exception as e:
        print("Decryption failed:", e)

if __name__ == '__main__':
    main()
