#----------------------------------
# Name:
# Program: Server.py
# CMPT361 Fall Project


import socket
import sys
import os 
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def server():
	

	#Server port
	serverPort = 13000
	
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
				clientInfo = connectionSocket.recv(2048).decode('ascii')
				print(clientInfo)
				
				#decrypt client info
				#check if client info valid
				valid = True
				if valid == True:
					#generate symm key here
					#send symm key to client here
					symmKey = "KEY" # replace
					connectionSocket.send(symmKey.encode('ascii'))
					
					print("Connection Accepted and Symmetric Key Generated for client:")
				else:
					invalidMessage = "Invalid username or password"
					connectionSocket.send(invalidMessage.encode('ascii'))
					print("The received client information: " + "is invalid (Connection Terminated).")
					connectionSocket.close()
				
				#receive client OK
				clientConfirm = connectionSocket.recv(2048).decode('ascii')
				print(clientConfirm)
				#decrypt confirmation here
				
				menu = "Select the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\nChoice: "
				connectionSocket.send(menu.encode('ascii'))
				
				
				userChoice = connectionSocket.recv(2048).decode('ascii')
				#decrypt userchoice here
				
				while (userChoice != "4"):
				
					if userChoice == "1":
						sendEmail()

					elif userChoice == "2":
						viewInbox()

					elif userChoice == "3":
						viewEmail()
						
					else:
						continue
						
					userChoice = connectionSocket.recv(2048).decode('ascii')
				
				
				terminateMessage = "Terminating connection with " + "<insert username>"
				#encrypt terminateMessage here 
				connectionSocket.send(terminateMessage.encode('ascii'))
				print(terminateMessage)
				connectionSocket.close()

				##############################################################
				return
				
			#Else, server/parent closes duplicate reference to connection socket
			connectionSocket.close() #ie. client-child process still has ref to conn socket
		
		except socket.error as e:
			print('Error occurred: ', e)
			serverSocket.close()
			sys.exit(1)
		except:
			print('Goodbye')
			serverSocket.close()
			sys.exit(0)



###########################################################
#menu Functions
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




#---------
server()
