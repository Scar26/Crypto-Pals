from Challenge9 import pkcs7 as pad
from Crypto.Cipher import AES
import binascii
import random
import os

def checkECB(data, block_size):
  n = len(data)//block_size
  for i in range(n):
    for j in range(i+1,n):
      if data[i*block_size:(i+1)*block_size] == data[j*block_size:(j+1)*block_size]:
        return True
  return False

def oracle(inp):
    key = os.urandom(16)
    iv = os.urandom(16)
    
    if random.randint(0,1):
        cipher = AES.new(key, AES.MODE_ECB)
        mode = 'ECB'
    else:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        mode = 'CBC'
        
    inp = os.urandom(1)*random.randint(5,10) + inp + os.urandom(1)*random.randint(5,10)
    if len(inp)%16 != 0:
        inp = pad(inp, (len(inp)//16+1)*16)
    return (binascii.hexlify(cipher.encrypt(inp)).decode(), mode)

def detect_mode(oracle):
    resp, actual_mode = oracle(b'a'*50)
    if checkECB(resp, 32):
        predicted_mode = 'ECB'
    else:
        predicted_mode = 'CBC'
    success = actual_mode == predicted_mode
    return (predicted_mode, success)

if __name__ == '__main__':
    print(all([detect_mode(oracle)[1] for _ in range(1000)]))