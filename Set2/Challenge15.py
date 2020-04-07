def pkcs7_unpad(s):
    byte = s[-1]
    if s[-byte:] == bytes([byte])*byte:
        s = s[:-byte]
    else:
        raise Exception('incorrect padding')
    return s