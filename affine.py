import math

def preprocess_text(text: str) -> str:
    """Converts text to uppercase and removes non-alphabetic characters."""
    return ''.join([c.upper() for c in text if c.isalpha()])

def is_coprime(a: int, m: int = 26) -> bool:
    """Checks if a and m are coprime."""
    return math.gcd(a, m) == 1

def encrypt_message(plaintext: str, a: int, b: int) -> str:
    """Encrypts plaintext using the Affine cipher."""
    if not is_coprime(a):
        raise ValueError("a must be coprime with 26")
    return ''.join([chr(((a * (ord(c) - ord('A')) + b) % 26) + ord('A')) 
                   for c in plaintext])

def decrypt_cipher(ciphertext: str, a: int, b: int) -> str:
    """Decrypts ciphertext using the Affine cipher."""
    if not is_coprime(a):
        raise ValueError("a must be coprime with 26")
    a_inv = pow(a, -1, 26)
    return ''.join([chr((a_inv * (ord(c) - ord('A') - b) % 26) + ord('A')) 
                   for c in ciphertext])

def find_switch_key(crypt_text: str, uncrypt_text: str) -> int:
    """Finds the 'a' key when b=0 using known plaintext-ciphertext pairs."""
    if len(crypt_text) != len(uncrypt_text):
        return -1
    for a in range(1, 26):
        if is_coprime(a) and encrypt_message(uncrypt_text, a, 0) == crypt_text:
            return a
    return -1

def main():
    """Main menu-driven interface."""
    while True:
        print("\n=== Affine Cipher Toolkit ===")
        print("1. Encrypt\n2. Decrypt\n3. Find Switch Key\n4. Exit")
        choice = input("Choose operation (1-4): ").strip()

        if choice in ('1', '2'):
            try:
                a = int(input("\nEnter value for 'a' (must be coprime with 26): "))
                while not is_coprime(a):
                    print("Invalid! 'a' must be coprime with 26.")
                    a = int(input("Try again: "))
                
                b = int(input("Enter value for 'b': "))
                text = preprocess_text(input("Enter text: "))
                
                if choice == '1':
                    result = encrypt_message(text, a, b)
                    print("\nEncrypted Message:", result)
                else:
                    result = decrypt_cipher(text, a, b)
                    print("\nDecrypted Message:", result)
            
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == '3':
            crypt = preprocess_text(input("\nEnter encrypted text: "))
            plain = preprocess_text(input("Enter corresponding decrypted text: "))
            key = find_switch_key(crypt, plain)
            
            if key != -1:
                print(f"\nFound Switch Key: a = {key}")
            else:
                print("\nNo valid key found. Ensure:")
                print("- Texts are the same length")
                print("- Encryption used b=0")
                print("- Valid 'a' exists")

        elif choice == '4':
            print("\nExiting program...")
            break

        else:
            print("\nInvalid choice! Please try again.")

        if input("\nReturn to main menu? (Y/N): ").upper() != 'Y':
            print("\nThank you for using the toolkit!")
            break

if __name__ == "__main__":
    main()