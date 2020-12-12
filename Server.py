#----------------------------------
# Name:
# Program: Server.py
# CMPT361 Fall Project


import socket
import sys
import os 
import random
import json
import time
import datetime

from Crypto.Cipher import AES
#from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

def server():
	#SAVE_PATH = ("/home/sharon/Documents/")
	SAVE_PATH = ("/home/kali/Desktop/")

	#Server port
	serverPort = 13000
	MENU = "Select the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\nChoice: "

	#Server sockets: uses IPv4 and TCP protocols
	try:
		serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except socket.error as e:
		print('Error in creating server socket: ', e)
		sys.exit(1)
	
	#Associate port# 13000 to server socket
	try:
		serverSocket.bind(('', serverPort))
	except socket.error as e:
		print('Error in binding server socket: ', e)
		sys.exit(1)
	
	print('The server is ready to accept connections.')
	
	#Server is only available to connect to one client at a time in its queue
	serverSocket.listen(5)
	
	while 1:

		try:

			#Server accepts ONE client connection
			connectionSocket, addr = serverSocket.accept()
			pid = os.fork() #Process ID 
			
			#If it's a client-child process
			if pid == 0:
				#Close duplicate reference from child 
				serverSocket.close() #ie. server still references socket server
				
				##############################################################
				#Communication Exchange

				
				
				#Server sends welcome to client & receives their name

				#clientInfo = connectionSocket.recv(2048) #X?X?X?X?XX?X?X?

				clientInfo = connectionSocket.recv(2048).decode('ascii')	#replace			

				#decrypt client info

				#decClientInfo = decryptionPublic(clientInfo) #correct

				#decClientInfo = clientInfo #replace

				
	
				#check if client info valid
				info_split = clientInfo.split('\n')
				userName = info_split[0]
				userPassword = info_split[1]		
				print(userName)		
				valid = checkClient(userName,userPassword) #validity variable
				
				if valid == True:
					#generate symm key here

					session_key = generateKey()				
		
					#send symm key to client here
					#symmKey = encryptSymKey(userName)
					connectionSocket.send(session_key) #ecrypt key here
					
					print("Connection Accepted and Symmetric Key Generated for client:")


				else:
					invalidMessage = "Invalid username or password"
					connectionSocket.send(invalidMessage.encode('ascii')) #X?X?X?X?X?X?X
					print("The received client information: " + "is invalid (Connection Terminated).")
					connectionSocket.close()

				
				#receive client OK
				clientConfirm = connectionSocket.recv(2048) #X?X?X?X?X?X?X?
				print(decrypt(clientConfirm, session_key))
				#decrypt confirmation here
				

				#connectionSocket.send(menu.encode('ascii'))
				
				
				#userChoice = connectionSocket.recv(2048).decode('ascii')
				userChoice = "0"
				
				#decrypt userchoice here

				
				connectionSocket.send(encrypt(MENU,session_key)) #X?X?X?X?X?X?X?X

				userChoice = decrypt(connectionSocket.recv(2048), session_key) #X?X?X?X?X?X?X?

				while (userChoice != "4"):
				
					if userChoice == "1":
						connectionSocket.send(encrypt("Send the email", session_key))
						receiveEmail(connectionSocket, SAVE_PATH, session_key)
						

					elif userChoice == "2":
						connectionSocket.send(encrypt("2", session_key))
						viewInbox(connectionSocket, SAVE_PATH, session_key)
						
					elif userChoice == "3":
						connectionSocket.send(encrypt("3", session_key))
						viewEmail(connectionSocket, SAVE_PATH, session_key)
						
					else:
						connectionSocket.send(encrypt(MENU,session_key))
						
					userChoice = decrypt(connectionSocket.recv(2048), session_key)
				
				
				terminateMessage = "4"
				#encrypt terminateMessage here 
				connectionSocket.send(encrypt(terminateMessage, session_key))
				print("Connection terminated")
				connectionSocket.close()

				##############################################################
				return
				
			#Else, server/parent closes duplicate reference to connection socket
			connectionSocket.close() #ie. client-child process still has ref to conn socket
		
		except socket.error as e:
			print('Error occurred: ', e)
			serverSocket.close()
			sys.exit(1)
	
		#except Exception as inst:
			#print("Error with", inst)



###########################################################
#menu Functions
###########################################################

def receiveEmail(connectionSocket, SAVE_PATH, session_key):
	emailFrom = decrypt(connectionSocket.recv(2048), session_key)
	connectionSocket.send(encrypt("Send to: ", session_key))
	emailTo = decrypt(connectionSocket.recv(2048), session_key)
	connectionSocket.send(encrypt("Title: ", session_key))
	emailTitle = decrypt(connectionSocket.recv(2048), session_key)
	connectionSocket.send(encrypt("Message: ", session_key))
	emailMessage = decrypt(connectionSocket.recv(2048), session_key)
	emailLength = str(len(emailMessage))
	emailTime = str(datetime.datetime.now())
	email = "From: " + emailFrom + "\nTo: " + emailTo + "\nTime and Date: " + emailTime + "\nTitle: " + emailTitle + "\nContent length: " + emailLength + "\nContent: " + emailMessage

	connectionSocket.send(encrypt("TERMINATE", session_key))

	emailToList = emailTo.split(";")

	for e in emailToList :

		path = SAVE_PATH + e + "/"
		name = os.path.join(path, emailTitle + ".txt")
		file1 = open(name, "w")
		file1.write(email)
		file1.close()

	print("An email from " + emailFrom + " is sent to " + emailTo + ", has a content length " + emailLength + ".")

	
def viewInbox(connectionSocket, SAVE_PATH, session_key):
	username = decrypt(connectionSocket.recv(2048), session_key)
	path = SAVE_PATH + username + "/"
	clientMail = os.listdir(path)
	index = 1
	for mail in clientMail:
		with open(path + mail, 'r') as file1:
			for line in file1:
				if line.split(":")[0] == "From":
					Sender = line.split(": ")[1].rstrip()
				if line.split(":")[0] == "Time and Date":
					timeSent = line.split(": ")[1].rstrip()
				if line.split(":")[0] == "Title":
					title = line.split(": ")[1].rstrip()
					
		mailIndex = str(index)
		email = mailIndex + "\t" + Sender + "\t" + timeSent + "\t" + title
		connectionSocket.send(encrypt(email, session_key))
		time.sleep(0.0001)
		index += 1
		
	connectionSocket.send(encrypt("TERMINATE", session_key))

def viewEmail(connectionSocket, SAVE_PATH, session_key):
	username = decrypt(connectionSocket.recv(2048), session_key)
	path = SAVE_PATH + username + "/"
	clientMail = os.listdir(path)
	connectionSocket.send(encrypt("Enter the email index you wish to view: ", session_key))
	index = decrypt(connectionSocket.recv(2048), session_key)
	file1 = open(path + clientMail[int(index) -1], 'r')
	for line in file1:
		connectionSocket.send(encrypt(line.rstrip(), session_key))
		time.sleep(0.0001)
	connectionSocket.send(encrypt("TERMINATE", session_key))
	
	
	
###########################################################
#encryption/decryption Functions
###########################################################
def checkClient(name, password):
	with open('user_pass.json') as file:
		data = json.load(file)
	if name in data and data[name] == password:
		return True
	else:
		return False
		
def fileHandler(fname):
	keyFile = open(fname, "rb")
	content = keyFile.read()
	return content

def getPubKey():
	pubKey = fileHandler("server_public.pem")
	print(pubKey)
	return pubKey

def getPrivKey():
	privKey = fileHandler("server" + "_private.pem")
	return privKey

def decryptionPublic(encryptedMessage):
	pubKey = RSA.importKey(getPubKey()) #here
	cipher_rsa_dec = PKCS1_OAEP.new(pubKey)
	dec_data = cipher_rsa_dec.decrypt(encryptedMessage)
	return unpad(dec_data)


#########################################################
#use client public RSA key to encrypt generated AES key
#Reference: https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-rsa

def getClientPubKey(clientName):
	pubClientKey = fileHandler(clientName + "_public.pem")
	return pubClientKey


def encryptionPublicClient(message):
	pubkey = RSA.importKey(getPubKey()) #here
	cipher_rsa_en = PKCS1_OAEP.new(pubkey)
	#session_key = generateSessionKey()
	enc_session_key = cipher_rsa_en.encrypt(message)
	return pad(enc_session_key)


def generateKey():
	session_key = get_random_bytes(16)
	return session_key

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

def encryptKey(session_key):
	recipient_key = RSA.importKey(getPubKey())
	session_key = get_random_bytes(16)

	cipher_rsa = PKCS1_OAEP.new(recipient_key)
	enc_session_key = cipher_rsa.encrypt(session_key)
	return enc_session_key

def decryptKey(session_key):
	recipient_key = RSA.importKey(getPubKey())
	cipher_rsa = PKCS1_OAEP.new(recipient_key)
	dec_session_key = cipher_rsa.decrypt(session_key)
	return dec_session_key

#####################################################
#PADDING SECTION

def pad(s):
	while len(s) % 16 != 0:
		s = s + "{"
	lambda s: s + (16 - len(s) % 16) * '{'
	return s

def unpad(message):
	
	message = message.rstrip('{')
	return message




#---------
server()

