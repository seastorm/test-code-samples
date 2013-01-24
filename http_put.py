#!/usr/bin/python

import socket
import sys


def check_put(server, port):
	print "Checking if server %s:%i allows PUT method..." % (server, port)
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ret = None
	try:
		s.settimeout(2)
		s.connect((server, port))

		req = 'OPTIONS / HTTP/1.1\n'
		req += 'Host: %s\n' % server
		req += '\n'

		s.send(req)
		res = s.recv(1024)
		#print res
		if 'PUT' in res:
			ret = True
		else:
			ret = False
		s.close()
	except Exception as e:
		print e
		return False

	return ret

def get_http_req(server, remote_file, data):
	req = 'PUT /%s HTTP/1.1\n' % remote_file
	req += 'Host: %s\n' % server
	req += 'Content-Type: text/html\n'
	req += 'Content-Length: %i\n' % len(data)
	req += 'User-Agent: jmpesp\n'
	req += '\n'
	req += data + '\n'
	return req

def main(argv):
	if len(argv) < 4:
		print "\nUtility that uploads a file on a HTTP server which accepts the PUT method\n"
		print "Usage: %s <server>[:<port>] <local_file> <remote_file>\n" % argv[0]
		sys.exit(0)

	server 		= argv[1]
	local_file 	= argv[2]
	remote_file 	= argv[3]
	data = ''
	port = 80

	if len(argv[1].split(':')) == 2:
		server = argv[1].split(':')[0]
		port = argv[1].split(':')[1]

	try:
		print "Reading local file " + local_file
		with open(local_file, 'r') as f:
			data = f.read()
	except Exception as e:
		print e
		sys.exit(0)

	if check_put(server, port) == False:
		print "Server does not allow PUT method"
		sys.exit(0)

	req = get_http_req(server, remote_file, data)

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(3)
	try:
		print "Connecting to %s:%s" % (server, port)
		s.connect((server, port))

		print "Sending request..."
		s.send(req)

		res = s.recv(1024)

		if '100 Continue' in res:
			res = s.recv(1024)
	
		if '200 OK' in res:
			print "File already exists"
		elif '201 Created' in res:
			print "=== File created successfully ==="
		elif ('404 Object Not Found' in res) or ('403 Forbidden' in res) or ('404 Not Found' in res):
			print "Could not create file"
		else:
			print "Unknown result: \n%s" % res

		s.close()
	except Exception as e:
		print e
		sys.exit(0)

if __name__ == '__main__':
	main(sys.argv)
