#!/usr/bin/env python3
#sender.py

import os, sys, getopt, time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from netinterface import network_interface

NET_PATH = './'
OWN_ADDR = 'A'
SERVER = 'S'
# ------------       
# main program
# ------------

netif = network_interface(NET_PATH, OWN_ADDR)

keys = RSA.generate(2048)

# getting server publickey
server_publickey = RSA.import_key(open('server_keys/server_publickey.pem').read())

p = keys.publickey().export_key()
# Private key is d
# not stored for now
d = keys.export_key()
# 256 bit random nonce
nonce = Random.get_random_bytes(32)

t = time.time()
print(t)

msg = str(nonce) + "|" + str(p) + "|" + str(t)
print(nonce)
print("")
print(p)

pk_cipher = PKCS1_OAEP.new(server_publickey)

enc_msg = pk_cipher.encrypt(msg.encode())
msg_header = 'SERVER_AUTH|'.encode()
enc_msg = msg_header + enc_msg

netif.send_msg(SERVER, enc_msg)


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
netif = network_interface(NET_PATH, OWN_ADDR)
print('Main loop started...')
while True:
	msg = input('Type a message: ')
	dst = input('Type a destination address: ')

	netif.send_msg(dst, msg.encode('utf-8'))

	if input('Continue? (y/n): ') == 'n': break















