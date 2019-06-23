from binascii import hexlify

plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = b'ICE'

def repeatedkeyXOR(input, key):
	n = len(key)
	output = b''
	for i in range(len(input)):
		byte = input[i]
		output += bytes([byte^key[i%n]])

	return output

def  main():
	print(hexlify(repeatedkeyXOR(plaintext,key)).decode())

if __name__ == '__main__':
	main()