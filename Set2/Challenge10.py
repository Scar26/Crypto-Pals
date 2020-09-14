from Crypto.Cipher import AES
from Challenge09 import pkcs7
from base64 import b64decode as bd
from pwn import xor

key = 'YELLOW SUBMARINE'
IV = '\x00'*16

def decryptCBC(ciphertext, key, iv):
    n = len(ciphertext)
    assert(n%16 == 0)
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [iv] + [ciphertext[i*16:i*16+16] for i in range(n//16)]
    plaintext = []
    for i in range(n//16):
        plaintext = [xor(cipher.decrypt(blocks[n//16-i-1]), blocks[n//16-i-2])] + plaintext
    return plaintext

result = decryptCBC(bd(open('Challenge10input.txt', 'rb').read()), key, IV)
print (''.join([i.decode() for i in result[1:]]))