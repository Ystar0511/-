from AES_CBC import *

given_string = "ICE ICE BABY\x04\x04\x04\x04"
target_string = "ICE ICE BABY"

try:
    target_string.encode() == PKCS7_unpad(given_string.encode())
    print("Correct Padding!")
except:
    print("Incorrect Padding!")
