# Attack on Tiny Encryption Algorithm (TEA)
# by Vince Belanger
# CPS 472 - Computer & Network Security
# February 12, 2019
# University of Dayton - Dr. Yao

#v is plaintext, k is array key

l = []

def tea_encrypt(v, k):
	print "--Encryption starting--"
	y=v[0]
	z=v[1]
	sum=0
	delta=0x9e3779b9
	# original delta: 0x9e3779b9
	print "Plaintext: ",v

	sum += delta
	y += ((z << 4) + k[0]) ^ (z + sum) ^ ((z>>5) + k[1])
	#z += ((y << 4) + k[2]) ^ (y + sum) ^ ((y>>5) + k[3])
	print "\ny: ",y
	print "z: ",z

	v[0]=z
	v[1]=y
	print "\nCiphertext: ",v

# Open file, parse lines, and store in list l
def read_file():
	f = open('message_pairs', 'r')

	for line in f:
		# parse
		parsedline = line.split('\t')
		plaintext = parsedline[0]
		ciphertext = parsedline[1]
		plaintext = plaintext.split(' ')
		ciphertext = ciphertext.split(' ')

		# store
		y_plain = int(plaintext[0])
		z_plain = int(plaintext[1])
		y_cipher = int(ciphertext[0])
		z_cipher = int(ciphertext[1].strip())

		storedline = [y_plain, z_plain, y_cipher, z_cipher]
		l.append(storedline)

	print "> File stored"
		
# Guesses K0, computes corresponding K1, and tests if match
def attack():
	print "> Guessing key"
	full_key_flag = False
	k0_guess = 0

	while not full_key_flag:
		delta = 0x9e3779b9		

		y = l[0][0]
		z = l[0][1]
		c = l[0][3]
		k1_compute_1 = ((c-y) ^ ((z<<4) + k0_guess) ^ (z + delta)) - (z>>5)

		y = l[1][0]
		z = l[1][1]
		c = l[1][3]
		k1_compute_2 = ((c-y) ^ ((z<<4) + k0_guess) ^ (z + delta)) - (z>>5)
		
		if k1_compute_1 == k1_compute_2:
			i = 2
			while i < 12:
				y = l[i][0]
				z = l[i][1]
				c = l[i][3]
				k1_compute_i = ((c-y) ^ ((z<<4) + k0_guess) ^ (z + delta)) - (z>>5)
				if k1_compute_i != k1_compute_1:
					break
				i += 1
			if k1_compute_i == k1_compute_1:
				full_key_flag = True

		#emergency loop abort
		if k0_guess > 9999999:
			print "Guessing too high, assuming improper text pairs"
			break

		if not full_key_flag:
			k0_guess += 1

	if full_key_flag:
		print "> Keys found:\nK0 =",k0_guess,"\nK1 =",k1_compute_i

print "\nAttack on TEA v0.2 by Vince Belanger\n"
read_file()
attack()
print
