#!/usr/bin/env python3
#sender.py

import os, sys, getopt, time
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from Crypto.Util import Padding
from netinterface import network_interface
import functions
from getpass import getpass

NET_PATH = './'
OWN_ADDR = 'A'
SERVER = 'S'
# ------------       
# main program
# ------------

netif = network_interface(NET_PATH, OWN_ADDR)

keys = RSA.generate(2048)

# ----------------------------
# ------ PROTOCOL PT 1 -------
# ----------------------------
# getting server publickey
server_publickey = RSA.import_key(open('server_keys/server_publickey.pem').read())

user_publickey = keys.publickey().export_key()
#print(len(p))
# Private key is d
# not stored for now
user_privatekey = keys.export_key()
# 256 bit random nonce
nonce = Random.get_random_bytes(32)

# saving this to verify against server timestamp
t = time.time()

# create message to be encrypted
msg = user_publickey + nonce
enc_msg = functions.rsa_hybrid_encrypt(msg, server_publickey)

msg_header = 'SERVER_AUTH'.encode() + '|'.encode()

full_msg = msg_header + enc_msg

netif.send_msg(SERVER, full_msg)

# wait for response
status, svr_msg = netif.receive_msg(blocking=True)

msg_received = functions.rsa_hybrid_decypt(svr_msg, keys)

if nonce != msg_received[:32]:
	print("Invalid nonce returned by server. Terminating connection attempt.")
	exit(1)
if t - float(msg_received[32:]) > 120:
	print("Terminating connection request.")
	exit(1)
print("Successfully authenticated server.")
status, svr_msg = netif.receive_msg(blocking=False)

# ----------------------------
# ------ PROTOCOL PT 2 -------
# ----------------------------

uid = input("Enter User ID: ")
password = getpass("Enter Password: ")

pwmsg = uid + "|" + password + "|"+ str(time.time())
msglen = str(len(pwmsg))

#RSA PSS protocol for signature
hashpwdmsg = SHA256.new(pwmsg.encode())
print(type(hashpwdmsg))
sigpwdmsg = pss.new(keys).sign(hashpwdmsg)

#Building the message
msg_header = 'USER_AUTH'.encode() + '|'.encode()
enc_msg = functions.rsa_hybrid_encrypt((msglen + "|" + pwmsg).encode() + sigpwdmsg, server_publickey)

full_msg = msg_header + enc_msg

#Sending the message
netif.send_msg(SERVER, full_msg)

#Listening for response
status, svr_msg = netif.receive_msg(blocking=True)

#grabbing AES key to decrypt message body
msg_received = functions.rsa_hybrid_decypt(svr_msg, keys)

#chop off the key so that we don't find an early delimiter
find_delim = msg_received[16:]
#the index of where the signature actually starts b/c we know key length is 16
sig_start = find_delim.find("|".encode()) + 17
msg_sig = msg_received[sig_start:]
msg_key = msg_received[:sig_start - 1]
user_hash = SHA256.new(msg_key)
verifier = pss.new(server_publickey)
try:
	verifier.verify(user_hash, msg_sig)
	print("The signature is authentic")
except (ValueError, TypeError) as e:
	print(e)
	print("The signature is not authentic!")
	exit(1)
if time.time() - float(msg_key[16:]) > 120:
	print("Terminating connection request.")
	exit(1)
else:
	session_key = msg_key[:16]
	print("Session key retrieved")
	status, svr_msg = netif.receive_msg(blocking=False)

#Todo: Protocol Part 3 -- Main Body
'''
----------------------------
------ PROTOCOL PT 3 -------
----------------------------
'''

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















