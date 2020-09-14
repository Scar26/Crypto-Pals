import random
import os
from Challenge09 import pkcs7 as pad
from Challenge09 import pkcs7_unpad as unpad
from Crypto.Cipher import AES
import binascii

key = os.urandom(16)
cipher = AES.new(key, AES.MODE_ECB)

def encrypt(inp):
    if len(inp)%16 != 0:
        inp = pad(inp, (len(inp)//16+1)*16)
    return (binascii.hexlify(cipher.encrypt(inp)).decode())

def decrypt(inp):
    return unpad(cipher.decrypt(bytes.fromhex(inp)))

def escape(s):
    return s.replace(b'&', b'\\').replace(b'=', b'\\')

def json_to_kv(obj):
    return b'&'.join([key.encode('utf-8')+b'='+obj[key] for key in obj.keys()])

def kv_to_json(cookie):
    dict = {}
    for pair in cookie.split(b'&'):
        dict[pair.split(b'=')[0].decode()] = pair.split(b'=')[1]
    return dict

def profile_for(email):
    user = {
        'email': email,
        'uid': str(random.randint(10,99)).encode('utf-8'),
        'role': b'customer'
    }
    
    token = encrypt(json_to_kv(user))    
    return (user, token)

def authenticate(token):
    role = kv_to_json(decrypt(token))['role']
    return f'Signed in as: {role.decode()}'

def crack():
    enc1 = profile_for(b'scaar@pwn.com')[1]
    enc2 = profile_for(b'a'*10 + b'admin' + bytes([11])*11 + b'@pwn.com')[1]
    payload = enc1[:64] + enc2[32:64]
    print (authenticate(payload))

if __name__ == '__main__':
    crack()