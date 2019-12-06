#!/usr/bin/env python3
# sender.py

import os, sys, getopt, time

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from Crypto.Signature import pss
from Crypto.Util import Padding

from netinterface import network_interface

NET_PATH = './'
OWN_ADDR = 'S'
CLIENT = 'A'
user_public_key = None

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
    status, msg = netif.receive_msg(blocking=True)  # when returns, status is True and msg contains a message
    if status:
        header = msg[:msg.find('|'.encode())]
    if header.decode() == 'SERVER_AUTH':
        server_privatekey = RSA.import_key(open('server_keys/server_privatekey.pem').read())
        # decrypt symmetric key
        aes_key_enc = msg[-256:]
        pkcs_cipher = PKCS1_OAEP.new(server_privatekey)
        aes_key = pkcs_cipher.decrypt(aes_key_enc)
        # decrypt user's public key and nonce
        beginning_of_iv = msg.find('|'.encode()) + 1
        end_of_iv = msg.find('|'.encode())+1+AES.block_size
        iv = msg[beginning_of_iv:end_of_iv]
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        nonce_len = 32
        user_public_key_len = 450
        key_and_nonce = aes_cipher.decrypt(msg[end_of_iv:end_of_iv+user_public_key_len+nonce_len+14])
        key_and_nonce = Padding.unpad(key_and_nonce, AES.block_size)
        user_public_key = key_and_nonce[:user_public_key_len]
        nonce = key_and_nonce[user_public_key_len:]
        # generate a timestamp
        t = str(time.time()).encode()
        # encrypt with aes key
        nonce_and_timestamp_msg = nonce + t
        # Create new IV and append to encrypted nonce and timestamp
        new_iv = Random.get_random_bytes(AES.block_size)
        new_aes_cipher = AES.new(aes_key, AES.MODE_CBC, new_iv)
        padded_full_msg = Padding.pad(nonce_and_timestamp_msg, AES.block_size, style='pkcs7')
        to_client_msg = new_iv + new_aes_cipher.encrypt(padded_full_msg)
        netif.send_msg(CLIENT, to_client_msg)


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
