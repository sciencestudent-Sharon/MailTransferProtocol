#----------------------------------
# Name:
# Program: Client.py
# CMPT361 Fall Project


from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

#from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pubKeyGenerator():
	key = RSA.generate(2048)
	public_key = key.publickey().export_key()
	return public_key

def privKeyGenerator():
	keyLen = 256
	key = get_random_bytes(int(keyLen/8))
	return key
	
def pubkeyToFile(fname):
	newFile = open(fname, "wb")
	pubKey = pubKeyGenerator()
	newFile.write(pubKey)
	newFile.close()
	return pubKey
	

def privkeyToFile(fname):
	newFile = open(fname, "wb")
	privKey = privKeyGenerator()
	newFile.write(privKey)
	newFile.close()
	return privKey
	

def checkKeyFile(fname):
	f = open(fname, "rb")
	content = f.read()
	return content

def showKeys():
	pubkeyToFile("server_public.pem")
	privkeyToFile("server_private.pem")

	pubkeyToFile("client1_public.pem")
	pubkeyToFile("client2_public.pem")
	pubkeyToFile("client3_public.pem")
	pubkeyToFile("client4_public.pem")
	pubkeyToFile("client5_public.pem")
	
	privkeyToFile("client1_private.pem")
	privkeyToFile("client2_private.pem")
	privkeyToFile("client3_private.pem")
	privkeyToFile("client4_private.pem")
	privkeyToFile("client5_private.pem")

	
	
#------
showKeys()









