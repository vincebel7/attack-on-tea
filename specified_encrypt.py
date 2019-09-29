# Specified TEA encryption using set plaintext and key
# by Vince Belanger
# CPS 472 - Computer & Network Security
# January 29, 2019
# University of Dayton - Dr. Yao

#v is plaintext, k is array key

def tea_encrypt(v, k):
	print "--Encryption starting--"
	y=v[0]
	z=v[1]
	delta=0x9e3779b9
	# original delta: 0x9e3779b9
	print "Plaintext: ",v

	y += ((z << 4) + k[0]) ^ (z + delta) ^ ((z>>5) + k[1])
	#z += ((y << 4) + k[2]) ^ (y + sum) ^ ((y>>5) + k[3])
	print "\ny: ",y
	print "z: ",z

	v[0]=z
	v[1]=y
	print "\nCiphertext: ",v

def guess(y, z, c):
	print("Test function for guessing k1\n")
	y = int(y)
	z = int(z)
	c = int(c)
	k0_guess = 656578
	k1_compute = 0
	sum = 0x9e3779b9
	# step 1
	#c-y = ((z<<4) + k0_guess) ^ (z + sum) ^ ((z>>5) + k1_compute)
	
	# step 2
	#(z>>5) + k1_compute = (c-y) ^ ((z<<4) + k0_guess) ^ (z + sum)

	# step 3
	k1_compute = ((c-y) ^ ((z<<4) + k0_guess) ^ (z + sum)) - (z>>5)

	print "k1 guess:",k1_compute
	print "real k1: ",9999875

print "\nSpecified TEA encryption program by VB, for testing\n"

v=[30316, 1889]
k=[656578, 9999875, 999999, 999999]
tea_encrypt(v, k)
guess(30316, 1889, 2661672034)
