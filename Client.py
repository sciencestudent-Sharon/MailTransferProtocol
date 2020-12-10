#----------------------------------
# Name:
# Program: Client.py
# CMPT361 Fall Project



import socket
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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
		
		
		menu = clientSocket.recv(2048).decode('ascii')
		#decrypt menu message here
		choice = input(menu)	
			
		#encrypt choice here
		clientSocket.send(choice.encode('ascii'))	
			
		#userNameRequest = clientSocket.recv(2048).decode('ascii')
		#reply = input(userNameRequest)
		
		while (choice != "4"):
			
			if choice == "1":
				sendEmail()

			elif choice == "2":
				viewInbox()

			elif choice == "3":
				viewEmail()

			else:
				choice = input(menu)
				continue
				
			choice = input(menu)
			#encrypt choice here
			clientSocket.send(choice.encode('ascii'))
			
		
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

def sendEmail():
	print("call to send email protocol")


def viewInbox():
	print("call to view inbox protocol")

def viewEmail():
	print("call to view email")


###########################################################
#encryption/decryption Functions
###########################################################



#------
client()
