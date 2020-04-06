from Crypto.Cipher import AES
from base64 import b64decode as bd

if __name__ == '__main__':
    key = b"YELLOW SUBMARINE"
    cipher = AES.new(key,AES.MODE_ECB)
    result = cipher.decrypt(bd(open('Challenge7input.txt','r').read()))

    print(result)