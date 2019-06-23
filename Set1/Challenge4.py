frequencies = { 
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}

def how_englishy(input):
	score = 0
	for byte in input:
		score += frequencies.get(chr(byte).lower(), 0)
	return score

def byteXOR(input, key): #Key is the character against which each byte is to be XORed
	xored = b''
	for byte in input:
		xored += bytes([byte^key])

	return xored

def XORbruteforce(ciphertext): #the ciphertext here is supposed to be a bytesequence, not an encoded string. Use the bytes module or b'' to convert it
	
	candidates = []

	for key in range(256):
	    plaintext = byteXOR(ciphertext, key)
	    candidate = how_englishy(plaintext)

	    result = {
	            'key': key,
	            'score': candidate,
	            'plaintext': plaintext
	        }

	    candidates.append(result)

	return sorted(candidates, key=lambda c: c['score'], reverse=True)[0]


def main():
	hexes = open('Challenge4input.txt','rb').read().decode().split("\n")
	solved = []
	for i in hexes:
	    solved.append(XORbruteforce(bytes.fromhex(i))['plaintext'])

	most_probable_solution = solved[0]
	for i in solved:
	    if how_englishy(i)>how_englishy(most_probable_solution):
	        most_probable_solution = i

	print(most_probable_solution.decode().rstrip())

if __name__ == "__main__":
	main()