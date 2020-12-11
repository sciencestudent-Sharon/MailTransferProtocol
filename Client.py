#----------------------------------
# Name:
# Program: Client.py
# CMPT361 Fall Project



import socket
import sys

from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad

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
		
		#here, encryption with server public key on clientinfo
		#send client info
		clientSocket.send(clientInfo.encode('ascii'))
		
		
		message = clientSocket.recv(2048).decode('ascii')
		print(message)
		
		if message == "Invalid username or password":
			print("Invalid username or password\nTerminating.")
			clientSocket.close()
		else:
			#decrypt message here
			#store key here
			#encrypt symmetric key here
			confirm = "OK"
			clientSocket.send(confirm.encode('ascii'))
		
		
		#menu = clientSocket.recv(2048).decode('ascii')
		#decrypt menu message here
		#choice = input(menu)	
			
		#encrypt choice here
		#clientSocket.send(choice.encode('ascii'))	
			
		#userNameRequest = clientSocket.recv(2048).decode('ascii')
		#reply = input(userNameRequest)

		
		received = clientSocket.recv(2048).decode('ascii')

		choice = "0"
		while (received != "4"):
	
			if received == "Send the email":
				choice = sendEmail(clientSocket, username)
				clientSocket.send(choice.encode('ascii'))

			elif received == "2":
				choice = viewInbox(clientSocket, username)
				clientSocket.send(choice.encode('ascii'))

			elif received == "3":
				viewEmail()
				choice = input("Choice: ")
				clientSocket.send(choice.encode('ascii'))

			else:
				choice = input(received)
				clientSocket.send(choice.encode('ascii'))
				#choice = input(menu)
				
			
			#encrypt choice here
			received = clientSocket.recv(2048).decode('ascii')
			
			
		
		serverTerminate = clientSocket.recv(2048).decode('ascii')
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

def sendEmail(clientSocket, username):
	choice = username
	clientSocket.send(choice.encode('ascii'))
	message = clientSocket.recv(2048).decode('ascii')
	while message != "TERMINATE":
		choice = input(message)
		clientSocket.send(choice.encode('ascii'))
		message = clientSocket.recv(2048).decode('ascii')
		
	print("The message is sent to the server")
	return "0"

def viewInbox(clientSocket, username):
	choice = username
	clientSocket.send(choice.encode('ascii'))
	message = clientSocket.recv(2048).decode('ascii')
	while message != "TERMINATE":
		print(message)
		message = clientSocket.recv(2048).decode('ascii')
	return "0"

def viewEmail():
	print("call to view email")


###########################################################
#encryption/decryption Functions
###########################################################



#------
client()
