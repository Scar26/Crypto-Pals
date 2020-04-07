import os
import binascii
from Crypto.Cipher import AES
from Challenge9 import pkcs7 as pad
from Challenge11 import detect_mode
from base64 import b64decode as bd
import random

salt = os.urandom(random.randint(10,100))
secret = bd("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK""")
key = os.urandom(16)
cipher = AES.new(key, AES.MODE_ECB)

def ECB_oracle(inp):
    inp = salt + inp + secret
    if len(inp)%16 != 0:
        inp = pad(inp, (len(inp)//16+1)*16)
    return (binascii.hexlify(cipher.encrypt(inp)).decode(), 'ECB')

def first_change(oracle, payload):
    base = oracle(b'')[0]
    base_blocks = [base[i*32: (i+1)*32] for i in range(len(base)//32)]
    resp = oracle(payload)[0]
    blocks = [resp[i*32: (i+1)*32] for i in range(len(resp)//32)]
    for i in range(len(base_blocks)):
        if base_blocks[i] != blocks[i]:
            return i

def get_offset(oracle):
    first = first_change(oracle, b'a')
    for i in range(1,16):
        if oracle(b'a'*i)[0][first*32: (first+1)*32] == oracle(b'a'*(i+1))[0][first*32: (first+1)*32]:
            return ((first+1)*32, i)
            
def leak_ECB_secret(oracle):
    mode, confirmation = detect_mode(oracle)
    assert(confirmation)
    if mode != 'ECB':
        print('The oracle is not ECB')
        return -1    
    print('ECB Oracle detected')
    
    offset, buffer = get_offset(oracle)
      
    blength = 0
    while True:
        a1 = oracle(b'x'*buffer + b'a'*blength)[0]
        a2 = oracle(b'x'*buffer + b'a'*(blength+1))[0]
        if a1[offset: offset + 32] == a2[offset: offset + 32]:
            break
        blength += 1
    print(f'Found Block length: {blength}')
    
    blocks_to_be_scanned = 10
    secret = b''
    for block in range(blocks_to_be_scanned):
        for i in range(1, blength + 1):
            payload = b'x'*buffer + b'a'*(blength - i)
            h = oracle(payload)[0][offset + block*32: offset + (block+1)*32]
            payload += secret
            for byte in range(256):
                if oracle(payload + bytes([byte]))[0][offset + block*32: offset + (block+1)*32] == h:
                    secret += bytes([byte])
    
    print ('##################')
    print (secret[:-1].decode())

leak_ECB_secret(ECB_oracle)