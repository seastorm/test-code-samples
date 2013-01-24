#!/usr/bin/python
import socket
import sys
import time
from threading import Thread

def myprint(msg):
	sys.stdout.write(msg)
	sys.stdout.flush()

def run(srv_address, usr_list, i):
	# print "Thread " + str(i) + " started"

	# Create a socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	# Connect to the server
	s.connect((srv_address, 25))

	# Receive the banner
	banner = s.recv(1024)
	# print banner

	# VRFY all users from list
	while 1:
		try:
			username = usr_list.pop()
			username = username[:-1]
			if (len(username) != 0):
				s.send('VRFY ' + username + '\r\n')
				result = s.recv(1024)
				if result[0:3] == '250' or result[0:3] == '252':
					print "\n" + username  + "\t\t[thread " + str(i) + "]"
				elif result[0:3] == '421':
					s.close()
					myprint('-')
					time.sleep(3)
					s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					s.connect((srv_address, 25))
					banner = s.recv(1024)
				else:
					myprint('.')
		except Exception as e:
			myprint('+')
			#print e
			break
		
	# Close the socket
	s.close()



# Main

if len(sys.argv) < 3:
	print "Simple script to verify the existance of a list of usernames on a mail servers"
	print "Usage: vrfy.py <server> <usernames_file> [<num_threads>]"
	sys.exit(0)

srv_address = sys.argv[1]
print "Checking users on mail server " + srv_address + "..."

f = open(sys.argv[2], 'r')
usr_list = f.readlines()
f.close()

print "Loaded " + str(len(usr_list)) + " usernames"

if len(sys.argv) == 4:
	num_threads = int(sys.argv[3])
else:
	num_threads = 20

print "Starting " + str(num_threads) + " threads"

for i in range(num_threads):
	t = Thread(target=run, args=(srv_address, usr_list, i))
	t.start()



