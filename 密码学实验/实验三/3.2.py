import random
from math import gcd


def mod_inverse_custom(a, m):
    """自定义模逆元实现"""

    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd_val, x, _ = extended_gcd(a, m)
    if gcd_val != 1:
        raise ValueError(f"模逆元不存在")
    return x % m


def is_prime(n):
    """判断一个数是否为素数"""
    if n <= 1:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n ** 0.5) + 1, 2):
        if n % i == 0:
            return False
    return True


def generate_large_prime(bits=16):
    """生成一个大素数"""
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num


def generate_rsa_keys(bits=16):
    while True:
        p = generate_large_prime(bits)
        q = generate_large_prime(bits)
        while p == q:
            q = generate_large_prime(bits)
        n = p * q
        phi_n = (p - 1) * (q - 1)
        e = 3
        if gcd(e, phi_n) == 1:
            break
    # 使用自定义的模逆元函数
    d = mod_inverse_custom(e, phi_n)
    return (e, n), (d, n)


def encrypt(m, pub_key):
    e, n = pub_key
    encrypted = [pow(ord(char), e, n) for char in m]
    return encrypted


def decrypt(c, priv_key):
    d, n = priv_key
    decrypted = ''.join(chr(pow(char, d, n)) for char in c)
    return decrypted


def rsa_test():
    pub_key, priv_key = generate_rsa_keys(bits=16)
    print("Public key:", pub_key)
    print("Private key:", priv_key)
    message = "Hello, RSA!"
    encrypted_message = encrypt(message, pub_key)
    print("Ciphertext:", encrypted_message)
    decrypted_message = decrypt(encrypted_message, priv_key)
    print("Plaintext:", decrypted_message)


rsa_test()