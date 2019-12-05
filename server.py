#!/usr/bin/env python3
#sender.py

import os, sys, getopt, time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from netinterface import network_interface

NET_PATH = './'
OWN_ADDR = 'S'

# ------------       
# main program
# ------------
netif = network_interface(NET_PATH, OWN_ADDR)
while True:
# Calling receive_msg() in non-blocking mode ...
#	status, msg = netif.receive_msg(blocking=False)
#	if status: print(msg)      # if status is True, then a message was returned in msg
#	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...
	status, msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message
	if status:
		header = msg[:msg.find('|'.encode())]
		if header.decode() == 'SERVER_AUTH':
			server_privatekey = RSA.import_key(open('server_keys/server_privatekey.pem').read())
			pk_cipher = PKCS1_OAEP.new(server_privatekey)
			dec_msg = pk_cipher.decrypt(msg[msg.find('|'.encode())+1:])
			print(dec_msg.decode())
	# print(msg.decode('utf-8'))



try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
	print('Usage: python sender.py -p <network path> -a <own addr>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python sender.py -p <network path> -a <own addr>')
		sys.exit(0)
	elif opt == '-p' or opt == '--path':
		NET_PATH = arg
	elif opt == '-a' or opt == '--addr':
		OWN_ADDR = arg

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
	print('Error: Cannot access path ' + NET_PATH)
	sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
	print('Error: Invalid address ' + OWN_ADDR)
	sys.exit(1)

# main loop

print('Main loop started...')
while True:
	msg = input('Type a message: ')
	dst = input('Type a destination address: ')

	netif.send_msg(dst, msg.encode('utf-8'))

	if input('Continue? (y/n): ') == 'n': break















