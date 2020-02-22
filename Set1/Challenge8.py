from binascii import a2b_hex

def checkECB(data, block_size):
  n = len(data)//block_size
  for i in range(n):
    for j in range(i+1,n):
      if data[i*block_size:(i+1)*block_size] == data[j*block_size:(j+1)*block_size]:
        return True
  return False

ciphertexts = open('Challenge8input.txt').read().split('\n')

for i in range(len(ciphertexts)):
    if checkECB(ciphertexts[i], 16):
        print(f"{i}th ciphertext is encrypted via ECB")