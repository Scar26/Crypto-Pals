from Challenge3 import byteXOR,how_englishy,XORbruteforce
from Challenge5 import repeatedkeyXOR
from itertools import combinations
import base64

a = b"this is a test"
b = b"wokka wokka!!!"

with open('Challenge6input.txt','rb') as inputfile:
	ciphertext = base64.b64decode(inputfile.read())

def hammingdistance(s1, s2):
    dist = 0

    for bit1, bit2 in zip(s1, s2):
        dist += sum([1 for bit in bin(bit1 ^ bit2) if bit == '1'])

    return dist

def getkeylengths(ciphertext):
	normalized_distances = []
	for k in range(1, 41):

		partitions = [ciphertext[i*k:(i+1)*k] for i in range(0, len(ciphertext))][:5]

		dist = 0
		pairs = combinations(partitions, 2)
		for (x, y) in pairs:
			dist += hammingdistance(x, y)

		obj = {
		'k' : k,
		'dist' : dist/k
		}
		normalized_distances.append(obj)

	return 	sorted(normalized_distances, key = lambda c: c['dist'])[:3]

def breakrepeatedkeyXOR(ciphertext):
	probable_key_sizes = getkeylengths(ciphertext)
	decrypted = []
	for key_length in probable_key_sizes:
		key = b''
		
		for i in range(key_length['k']):
			block = b''
			
			for j in range(i,len(ciphertext),key_length['k']):
				block += bytes([ciphertext[j]])


			key += bytes([XORbruteforce(block)['key']])
		obj = {
		'key' : key,
		'plaintext' : repeatedkeyXOR(ciphertext,key)
		}
		decrypted.append(obj)
	return sorted(decrypted, key = lambda c: how_englishy(c['plaintext']), reverse = True)[0]


if __name__ == '__main__':
	result = breakrepeatedkeyXOR(ciphertext)
	print('KEY : ',result['key'].decode())
	print('############################################')
	print(result['plaintext'].decode())