#----------------------------------
# Name:
# Program: Client.py
# CMPT361 Fall Project



import socket
import sys
import socket
import os 
import json
import time

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

from Crypto.Cipher import AES
#from Crypto.Util.Padding import pad, unpad

def client():

	
	#Server Information
	serverName = input('Enter the server IP or name: ')
	serverPort = 13000
	
	#Client socket: uses IPv4 & TCP protocols
	try:
		clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except socket.error as e:
		print('Error in creating client socket: ', e)
		sys.exit(1)
	
	try:
		#Client connect with server
		clientSocket.connect((serverName, serverPort))
		
		clientInfo = ""
		username = input("Enter your username: ")
		password = input("Enter your password: ")
		clientInfo += username + '\n' + password

		#clientInfo = encryptWithPublic(clientInfo)
		#public_key = clientInfo.publickey().exportKey() #here

		#here, encryption with server public key on clientinfo
		#send client info
		#clientSocket.send(encryptWithPublic(clientInfo)) #X?X?X?X?X?X?X?X?X?X?
		clientSocket.send(clientInfo.encode('ascii'))
		
		
		message = clientSocket.recv(2048) #X?X?X?X?X?X?X?X?
		#print(message) #<---------UNCOMMMENT
		#print(decrypt(pubEncMessage))
		#message = decryptionPublic(pubEncMessage) #correct
		#message = pubEncMessage.decode('ascii') #replace
	
		
		if message == "Invalid username or password":
			print("Invalid username or password\nTerminating.")
			clientSocket.close()
			return
		else:
			#decrypt message here
			#store key here
			#encrypt symmetric key here
			session_key = message
			clientSocket.send(encrypt("OK", session_key))
			
		
		
		#menu = clientSocket.recv(2048).decode('ascii')
		#decrypt menu message here
		#choice = input(menu)	
			
		#encrypt choice here
		#clientSocket.send(choice.encode('ascii'))	
			
		#userNameRequest = clientSocket.recv(2048).decode('ascii')
		#reply = input(userNameRequest)

		
		received = decrypt(clientSocket.recv(2048), session_key) #X?X?X?X?X?X?X?X?

		choice = "0"
		while (received != "4"):
	
			if received == "Send the email":
				choice = sendEmail(clientSocket, username, session_key)
				clientSocket.send(encrypt(choice, session_key))

			elif received == "2":
				choice = viewInbox(clientSocket, username, session_key)
				clientSocket.send(encrypt(choice, session_key))

			elif received == "3":
				choice = viewEmail(clientSocket, username, session_key)
				clientSocket.send(encrypt(choice, session_key))

			else:
				choice = input(received)
				clientSocket.send(encrypt(choice, session_key))
				
			
			#encrypt choice here
			received = decrypt(clientSocket.recv(2048), session_key)
			
			
		
		serverTerminate = encrypt(clientSocket.recv(2048),session_key)
		#decrypt serverTerminate here using sym_key
		print("The connection is terminated with the server.")
		clientSocket.close() 
		
	except socket.error as e:
		print('Error occurred: ', e)
		clientSocket.close()
		sys.exit(1)



###########################################################
#Functions
###########################################################

def sendEmail(clientSocket, username, session_key):
	choice = username
	clientSocket.send(encrypt(choice, session_key))
	message = decrypt(clientSocket.recv(2048), session_key)
	while message != "TERMINATE":
		choice = input(message)
		clientSocket.send(encrypt(choice, session_key))
		message = decrypt(clientSocket.recv(2048), session_key)
		
	print("The message is sent to the server")
	print()
	return "0"

def viewInbox(clientSocket, username, session_key):
	print("Index\tFrom\tDateTime\t\tTitle")
	choice = username
	clientSocket.send(encrypt(choice, session_key))
	message = decrypt(clientSocket.recv(2048), session_key)
	while message != "TERMINATE":
		print(message)
		message = decrypt(clientSocket.recv(2048), session_key)
	print()
	return "0"

def viewEmail(clientSocket, username, session_key):
	choice = username
	clientSocket.send(encrypt(choice, session_key))
	message = decrypt(clientSocket.recv(2048), session_key)
	choice = input(message)
	clientSocket.send(encrypt(choice, session_key))
	print()
	message = decrypt(clientSocket.recv(2048), session_key)
	while message != "TERMINATE":
		print(message)
		message = decrypt(clientSocket.recv(2048), session_key)
	print()
	return "0"

###########################################################
#encryption/decryption Functions
###########################################################
def fileHandler(fname):
	keyFile = open(fname, "rb")
	content = keyFile.read()
	return content
	
def getPubKey():
	pubKey = fileHandler("server_public.pem")
	return pubKey

def getPrivKey():
	privKey = fileHandler("server_private.pem")
	return privKey
	
def encryptWithPublic(message):
	pubkey = RSA.importKey(getPubKey()) #here
	cipher_rsa_en = PKCS1_OAEP.new(pubkey)
	enc_data = cipher_rsa_en.encrypt(pad(message).encode('ascii'))
	print(enc_data)
	return enc_data

def decryptionPublic(encryptedMessage):
	pubkey = RSA.importKey(getPubKey()) #here
	cipher_rsa_dec = PKCS1_OAEP.new(pubkey)
	dec_data = cipher_rsa_dec.decrypt(encryptedMessage)
	return unpad(dec_data)

def encrypt(message, session_key):
	message = pad(message)
	data = message.encode("utf-8")

	cipher_aes = AES.new(session_key, AES.MODE_ECB)
	ciphertext = cipher_aes.encrypt(data)
	return ciphertext

def decrypt(message, session_key):
	cipher_aes = AES.new(session_key, AES.MODE_ECB)
	data = cipher_aes.decrypt(message)
	return unpad(data.decode("utf-8"))

def decryptKey(session_key):
	recipient_key = RSA.importKey(getPubKey())
	cipher_rsa = PKCS1_OAEP.new(recipient_key)
	dec_session_key = cipher_rsa.decrypt(session_key)
	return dec_session_key
		

######################################################
def fileSymKey(clientName, encSymKey):
	keyFile = open(clientName + "_private.pem", "wb")
	keyFile.write(encSymKey)
	
########################################################
#PADDING SECTION

def pad(s):
	while len(s) % 16 != 0:
		s = s + "{"
	lambda s: s + (16 - len(s) % 16) * '{'
	return s

def unpad(message):
	message = message.rstrip('{')
	return message

	

#------
client()
