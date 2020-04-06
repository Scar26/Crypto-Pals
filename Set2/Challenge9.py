def pkcs7(s, l):
    byte = l-len(s)
    return s + bytes([byte])*byte

if __name__ == '__main__':
    print(pkcs7(b"YELLOW SUBMARINE", 20))