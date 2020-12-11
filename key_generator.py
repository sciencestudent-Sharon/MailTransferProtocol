#----------------------------------
# Name:
# Program: Client.py
# CMPT361 Fall Project


from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

#from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pubKeyGenerator(key):
	public_key = key.publickey().export_key()
	return public_key

def privKeyGenerator(key):
	private_key = key.export_key()
	return private_key
	
	
def pubkeyToFile(key, fname):
	newFile = open(fname, "wb")
	pubKey = pubKeyGenerator(key)
	newFile.write(pubKey)
	newFile.close()
	return pubKey
	

def privkeyToFile(key, fname):
	newFile = open(fname, "wb")
	privKey = privKeyGenerator(key)
	newFile.write(privKey)
	newFile.close()
	return privKey
	

def checkKeyFile(fname):
	f = open(fname, "rb")
	content = f.read()
	return content

def showKeys():
	key = RSA.generate(2048)
	
	pubkeyToFile(key, "server_public.pem")
	privkeyToFile(key, "server_private.pem")

	pubkeyToFile(key, "client1_public.pem")
	pubkeyToFile(key, "client2_public.pem")
	pubkeyToFile(key, "client3_public.pem")
	pubkeyToFile(key, "client4_public.pem")
	pubkeyToFile(key, "client5_public.pem")
	
	'''
	privkeyToFile("client1_private.pem")
	privkeyToFile("client2_private.pem")
	privkeyToFile("client3_private.pem")
	privkeyToFile("client4_private.pem")
	privkeyToFile("client5_private.pem")
	'''
	
	
#------
showKeys()









