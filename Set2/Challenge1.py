def pkcs7(s, l):
    byte = l-len(s)
    return s + chr(byte)*byte

if __name__ == '__main__':
    print(pkcs7("YELLOW SUBMARINE", 20))