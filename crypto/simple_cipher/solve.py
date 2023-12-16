from pwn import *


r = remote('chal.tuctf.com', 30004)


def bin2byte(inp):
	c = bytes.fromhex(hex(int(inp, 2))[2:].rjust(len(inp)//4, '0'))
	return c

def hex2bin(inp):
	return str(bin(int('1'+inp,base=16)))[3:]

def get_cipher(plain: bytes):
	r.sendlineafter(b'[4] Exit', b'1')
	r.sendlineafter(b'plaintext:', plain)
	key = b'00' * 6
	r.sendlineafter(b'(ex. 0011AABBCCDD):', key)
	r.recvuntil(b'Your ciphertext is: \n')
	c = r.recvline().strip().decode()
	return c

def get_boxes():
	sbox = [-1] * 48
	for i in range(48):
		plain = ['0'] * 48
		plain[i] = '1'
		plain = ''.join(plain)
		print(plain)
		p = bin2byte(plain)
		c = get_cipher(p)[:48]
		print(c)
		for j, bit in enumerate(c):
			if bit == '1':
				sbox[j] = i

	ubox = [-1] * 48
	for i, val in enumerate(sbox):
		ubox[val] = i

	return sbox, ubox

# reconstruct encrypt and decrypt boxes
sbox, ubox = get_boxes()
r.close()


flag = '110010100001000100101101001010111110010111001011100100100001010110111111111010001110011111011101101100000001100100001001111111110101010011110011000100000011000010000100111100011001010111010111101111100011010110100110100010010000011111100001100100100001100110100100100100110111001001010101'

#sbox = [41, 18, 30, 26, 15, 11, 14, 25, 40, 0, 47, 12, 28, 21, 32, 29, 20, 8, 19, 9, 22, 42, 36, 7, 10, 3, 31, 2, 5, 17, 13, 43, 27, 44, 6, 38, 24, 33, 23, 45, 1, 16, 4, 35, 34, 46, 39, 37]
#ubox = [9, 40, 27, 25, 42, 28, 34, 23, 17, 19, 24, 5, 11, 30, 6, 4, 41, 29, 1, 18, 16, 13, 20, 38, 36, 7, 3, 32, 12, 15, 2, 26, 14, 37, 44, 43, 22, 47, 35, 46, 8, 0, 21, 31, 33, 39, 45, 10]


def xor(ptext,key):
	text=''
	for i in range(0,48):
		text+=str(int(ptext[i])^int(key[i]))
	return text

def unscramble(scrambled_text):
	revPattern=ubox
	unscrambled_text=''
	for i in revPattern:
		unscrambled_text+=str(scrambled_text[i])
	return unscrambled_text

def substitution(ptext):
	pattern = sbox
	scrambled = ''
	for i in pattern:
		scrambled += str(ptext[i])
	return scrambled

def pad(ptext):
	if len(ptext)%48!=0:
		bitsToAdd =  48-(len(ptext)%48)
		add = ('0'*bitsToAdd)
		ptext+=add
	elif len(ptext)==0:
		ptext=('0'*48)
	return ptext

def encrypt(pt, key):
	#pt = str(input('Enter your plaintext: '))
	try:
		#key = input('Enter your 6 byte key (ex. 0011AABBCCDD): ').strip()
		binKey = str(bin(int('1'+key,base=16)))[3:]
	except:
		print('Invalid Key! Please ensure that your input is 6 bytes!')
		return -1
	if(len(binKey)!=48):
		print('Error with key! Please ensure key is 6 characters long!')
		return -1
	binPT=''
	for chr in pt:
		binPT+='{0:08b}'.format(ord(chr)) 
	binCText=''
	binPT=pad(binPT)
	for i in range(0,len(binPT),48):
		binCText+=xor(substitution(binPT[i:i+48]),binKey)
	print('\nYour ciphertext is: \n' + binCText+'\n\n')
	return binCText

def decrypt(ctext, key):
	#ctext = str(input('Enter your ciphertext as binary (ex. 0011001101010101000011110000000011111111): ')).strip()
	try:
		#key = input('Enter your 6 byte key (ex. 0011FFDDCCBB): ').strip()
		binKey = str(bin(int('1'+key,base=16)))[3:]
	except:
		print('Invalid Key! Please ensure that your input is 6 bytes!')
		return -1
	if(len(binKey)!=48):
		print('Error with key! Please ensure key is 6 characters long!')
		return -1
	binPText=''
	for i in range(0,len(ctext),48):
		binPText+=unscramble(xor(ctext[i:i+48],binKey))
	decodedMessage=''
	for i in range(0,len(binPText),8):
		decodedMessage+=str(chr(int(binPText[i:i+8],2)))
	print('\nHere is your plaintext back: \n ' + decodedMessage+'\n\n')


# recover the key
first_block = hex2bin(b'TUCTF{'.hex())
key = xor(substitution(first_block), flag[:48])


# decrypt
for i in range(0, len(flag), 48):
	u = unscramble(xor(flag[i:i+48], key))
	print(bin2byte(u).decode(), end='')
print()

