def pkcs7(s, l):
    byte = l-len(s)
    return s + bytes([byte])*byte

def pkcs7_unpad(s):
    byte = s[-1]
    if s[-byte:] == bytes([byte])*byte:
        s = s[:-byte]
    return s

if __name__ == '__main__':
    print(pkcs7(b"YELLOW SUBMARINE", 20))