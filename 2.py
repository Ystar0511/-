import string
from collections import Counter

def find_key_length(ciphertext, max_length=20):
    
    coincidences = []
    for length in range(1, max_length + 1):
        avg_coincidence = 0
        for i in range(length):
            segment = ciphertext[i::length]
            freq = Counter(segment)
            total = len(segment)
            if total == 0:
                continue
            coincidence = sum(count * (count - 1) for count in freq.values()) / (total * (total - 1))
            avg_coincidence += coincidence
        avg_coincidence /= length
        coincidences.append((length, avg_coincidence))

    coincidences.sort(key=lambda x: x[1], reverse=True)
    return coincidences[0][0]

def find_key_byte(ciphertext, key_length, index, english_freq):

    segment = ciphertext[index::key_length]
    if not segment:
        return 0

    freq = Counter(segment)
    total = len(segment)
    max_score = -1
    best_byte = 0
    for key_byte in range(256):
        score = 0
        for ct_byte, count in freq.items():
            pt_byte = ct_byte ^ key_byte

            if chr(pt_byte) in string.ascii_letters or chr(pt_byte) == ' ':
                prob = english_freq.get(chr(pt_byte).lower(), 0)
                score += count * prob
        if score > max_score:
            max_score = score
            best_byte = key_byte
    return best_byte

def decrypt(ciphertext, key):

    plaintext = bytearray()
    key_length = len(key)
    for i, ct_byte in enumerate(ciphertext):
        key_byte = key[i % key_length]
        plaintext.append(ct_byte ^ key_byte)
    return plaintext

def encrypt(plaintext, key):

    ciphertext = bytearray()
    key_length = len(key)
    for i, pt_byte in enumerate(plaintext):
        key_byte = key[i % key_length]
        ciphertext.append(pt_byte ^ key_byte)
    return ciphertext

def main():

    plaintext = b'This is a sample plaintext for Vigenere like XOR cipher.'
    key = b'secret'


    ciphertext = encrypt(plaintext, key)
    print(f"密文: {ciphertext}")


    guessed_key_length = find_key_length(ciphertext)
    print(f"猜测的密钥长度: {guessed_key_length}")


    english_freq = {
        'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
        'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094,
        'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
        'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929,
        'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
        'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
        'y': 0.01974, 'z': 0.00074
    }
    guessed_key = bytearray()
    for i in range(guessed_key_length):
        key_byte = find_key_byte(ciphertext, guessed_key_length, i, english_freq)
        guessed_key.append(key_byte)
    print(f"猜测的密钥: {guessed_key}")
    print(f"实际的密钥: {key}")


    decrypted = decrypt(ciphertext, guessed_key)
    print(f"解密结果: {decrypted.decode('ascii', errors='ignore')}")
    print(f"实际的明文: {plaintext.decode('ascii')}")

if __name__ == "__main__":
    main()