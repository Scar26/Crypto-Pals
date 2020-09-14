import os
import binascii
from Crypto.Cipher import AES
from Challenge09 import pkcs7 as pad
from Challenge11 import detect_mode
from base64 import b64decode as bd

secret = bd("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK""")
key = os.urandom(16)
cipher = AES.new(key, AES.MODE_ECB)

def ECB_oracle(inp):
    inp += secret
    if len(inp)%16 != 0:
        inp = pad(inp, (len(inp)//16+1)*16)
    return (binascii.hexlify(cipher.encrypt(inp)).decode(), 'ECB')

def leak_ECB_secret(oracle):
    mode, confirmation = detect_mode(oracle)
    
    assert(confirmation)
    
    if mode != 'ECB':
        print('The oracle is not ECB')
        return -1
    
    print('ECB Oracle detected')
    
    blength = 0
    while True:
        a1 = oracle(b'a'*blength)[0]
        a2 = oracle(b'a'*(blength+1))[0]
        if a1[:32] == a2[:32]:
            break
        blength += 1
    print(f'Found Block length: {blength}')
    
    blocks_to_be_scanned = 10
    secret = b''
    for block in range(blocks_to_be_scanned):
        for i in range(1, blength + 1):
            payload = b'a'*(blength - i)
            h = oracle(payload)[0][block*32:(block+1)*32]
            payload += secret
            for byte in range(256):
                if oracle(payload + bytes([byte]))[0][block*32:(block+1)*32] == h:
                    secret += bytes([byte])
    
    print ('##################')
    print (secret[:-1].decode())                        

if __name__ == '__main__':
    leak_ECB_secret(ECB_oracle)