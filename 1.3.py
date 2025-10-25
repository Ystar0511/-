import base64
from collections import Counter

def hamming_distance(s1, s2):
    """计算两个字节串的汉明距离"""
    if len(s1) != len(s2):
        raise ValueError("两个字节串长度必须相等")
    distance = 0
    for b1, b2 in zip(s1, s2):

        xor = b1 ^ b2
        distance += bin(xor).count('1')
    return distance

def find_key_length(ciphertext, max_length=40):
    """找到最可能的密钥长度"""
    distances = []
    for keysize in range(2, max_length + 1):

        blocks = [ciphertext[i:i+keysize] for i in range(0, 4*keysize, keysize) if i+keysize <= len(ciphertext)]
        if len(blocks) < 2:
            continue
        total_distance = 0
        pair_count = 0
        for i in range(len(blocks)):
            for j in range(i+1, len(blocks)):
                total_distance += hamming_distance(blocks[i], blocks[j])
                pair_count += 1
        if pair_count == 0:
            continue
        avg_distance = total_distance / pair_count
        normalized_distance = avg_distance / keysize
        distances.append((keysize, normalized_distance))

    distances.sort(key=lambda x: x[1])
    return [d[0] for d in distances[:3]]

def score_english(text):
    """根据英文字符频率计算文本的得分，得分越高越可能是英文"""
    # 英文字符（含空格）的频率表
    freq = {
        ' ': 13.0, 'e': 12.702, 't': 9.056, 'a': 8.167, 'o': 7.507,
        'i': 6.966, 'n': 6.749, 's': 6.327, 'h': 6.094, 'r': 5.987,
        'd': 4.253, 'l': 4.025, 'c': 2.782, 'u': 2.758, 'm': 2.406,
        'w': 2.360, 'f': 2.228, 'g': 2.015, 'y': 1.974, 'p': 1.929,
        'b': 1.492, 'v': 0.978, 'k': 0.772, 'j': 0.153, 'x': 0.150,
        'q': 0.095, 'z': 0.074
    }
    text = text.lower()
    count = Counter(text)
    total = sum(count.values())
    if total == 0:
        return 0
    score = 0
    for char, cnt in count.items():
        score += freq.get(char, 0) * (cnt / total)
    return score

def single_byte_xor(ciphertext):
    """破解单字节异或，返回最优密钥和明文"""
    best_score = 0
    best_key = 0
    best_plaintext = b''
    for key in range(256):
        plaintext = bytes([b ^ key for b in ciphertext])
        current_score = score_english(plaintext.decode('ascii', errors='ignore'))
        if current_score > best_score:
            best_score = current_score
            best_key = key
            best_plaintext = plaintext
    return best_key, best_plaintext

def break_repeating_key_xor(ciphertext):
    """破解重复密钥异或"""

    possible_key_lengths = find_key_length(ciphertext)
    best_key = b''
    best_plaintext = b''
    best_score = 0
    for keysize in possible_key_lengths:

        blocks = [ciphertext[i::keysize] for i in range(keysize)]

        key = []
        for block in blocks:
            key_byte, _ = single_byte_xor(block)
            key.append(key_byte)
        key = bytes(key)

        plaintext = bytes([ciphertext[i] ^ key[i % keysize] for i in range(len(ciphertext))])

        score = score_english(plaintext.decode('ascii', errors='ignore'))

        if score > best_score:
            best_score = score
            best_key = key
            best_plaintext = plaintext
    return best_key, best_plaintext

def main():
    # 读取base64编码的密文文件
    with open('ciphertext.txt', 'r') as f:
        base64_cipher = f.read()
    ciphertext = base64.b64decode(base64_cipher)

    key, plaintext = break_repeating_key_xor(ciphertext)
    print("密钥:", key.decode('ascii'))
    print("明文:", plaintext.decode('ascii', errors='ignore'))

if __name__ == "__main__":
    main()
