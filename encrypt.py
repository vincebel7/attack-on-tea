# Generating Plaintext and Corresponding 1-Round TEA Ciphertext
# by Vince Belanger
# CPS 472 - Computer & Network Security
# January 29, 2019
# University of Dayton - Dr. Yao

# v is plaintext, k is array key

from random import *

entries = 100
f = open('message_pairs', 'w+')

def generate(n):
	for x in range(1, n+1):
		y = randint(1, 99999) # random number up to 5 digits
		z = randint(1, 99999)
		f.write("%s %s" % (y, z))

		# call encryption
		v = [y, z]
		tea_encrypt(v, key)	

def tea_encrypt(v, k):
	y=v[0]
	z=v[1]
	delta=0x9e3779b9

	y += ((z << 4) + k[0]) ^ (z + delta) ^ ((z>>5) + k[1])

	v[0]=z
	v[1]=y
	
	f.write("\t%s %s\n" % (z, y))

print "\nTEA encryption program v0.2 by Vince Belanger"

print "Enter values to use for encryption key:"
k0 = input("K0:")
k1 = input("K1:")
key = [k0, k1]

generate(entries)

print "\n",entries,"plaintext/ciphertext pairs generated in file `message_pairs`"
