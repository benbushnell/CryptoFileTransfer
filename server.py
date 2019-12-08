#!/usr/bin/env python3
# sender.py

import os, sys, getopt, time, json

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from Crypto.Signature import pss
from Crypto.Util import Padding
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

import functions
from netinterface import network_interface

NET_PATH = './'
OWN_ADDR = 'S'
CLIENT = 'A'
user_auth_public_key = None
user_enc_public_key = None

# ------------       
# main program
# ------------
netif = network_interface(NET_PATH, OWN_ADDR)
serverauthcode = 0

# Calling receive_msg() in blocking mode ...
status, msg = netif.receive_msg(blocking=True)  # when returns, status is True and msg contains a message
if status:
    header = msg[:msg.find('|'.encode())]
if header.decode() == 'SERVER_AUTH':
    server_auth_privatekey = RSA.import_key(open('server_keys/server_auth_privatekey.pem').read())
    server_enc_privatekey = RSA.import_key(open('server_keys/server_enc_privatekey.pem').read())
    msg = msg[msg.find('|'.encode())+1:]
    # decrypt symmetric key
    # decrypt user's public key and nonce

    nonce_len = 32
    user_public_key_len = 450

    keys_and_nonce = functions.rsa_hybrid_decrypt(msg, server_enc_privatekey)

    user_auth_public_key = RSA.import_key(keys_and_nonce[:user_public_key_len])
    user_enc_public_key = RSA.import_key(keys_and_nonce[user_public_key_len:user_public_key_len * 2])
    nonce = keys_and_nonce[user_public_key_len * 2:]
    # generate a timestamp
    t = str(time.time()).encode()
    # encrypt with aes key
    nonce_and_timestamp_msg = nonce + t
    # Create new IV and append to encrypted nonce and timestamp
    to_client_msg = functions.rsa_hybrid_encrypt(nonce_and_timestamp_msg, user_enc_public_key)
    netif.send_msg(CLIENT, to_client_msg)
    serverauthcode = 1
    # TODO: figure out why this fixes an error where the first instance of receive_msg is not blocking
    status, msg = netif.receive_msg(blocking=False)

status, msg = netif.receive_msg(blocking=True)
if serverauthcode == 1:
    if status:
        header = msg[:msg.find('|'.encode())]
        if header.decode() == 'USER_AUTH':
            server_auth_privatekey = RSA.import_key(open('server_keys/server_auth_privatekey.pem').read())
            server_enc_privatekey = RSA.import_key(open('server_keys/server_enc_privatekey.pem').read())
            # Remove header
            msg = msg[msg.find('|'.encode()) + 1:]
            # Decrypt message
            msg = functions.rsa_hybrid_decrypt(msg, server_enc_privatekey)
            # Verify Signature
            sig_verified, pwmsg = functions.verify_signature(msg, user_auth_public_key)

            if sig_verified:
                print("The signature is authentic")
                pwmsg_parts = pwmsg.split("|".encode())
                uid = pwmsg_parts[0]
                ts = pwmsg_parts[2]
                pwd_hash = SHA256.new(pwmsg_parts[1])
                if not functions.is_timestamp_valid(time.time(), float(ts)):
                    print("Timestamp error")
                    exit(1)
                    # TODO: Send user error message
                else:
                    with open('info.json') as json_file:
                        data = json.load(json_file)
                        # check the user ID exists
                        if pwmsg_parts[0].decode() in data:
                            # check password
                            if pwd_hash.hexdigest() == data[uid.decode()].lower():
                                # Generate symmetric key (K_us) with scrypt
                                salt = get_random_bytes(16)
                                key = scrypt(pwmsg_parts[1].decode(), salt, 16, N=2**14, r=8, p=1)
                                # generate a timestamp
                                t = str(time.time()).encode()
                                msg_symm = key + t
                                # hash message
                                hash_msg_symm = SHA256.new(msg_symm)
                                # sign the hash
                                sig_hash_msg_symm = pss.new(server_auth_privatekey).sign(hash_msg_symm)
                                # concat signed hash to message
                                final_msg = (str(len(msg_symm)) + "|").encode() + msg_symm + sig_hash_msg_symm

                                #encrypt message
                                enc_full_msg = functions.rsa_hybrid_encrypt(final_msg, user_enc_public_key)

                                netif.send_msg(CLIENT, enc_full_msg)
                            else:
                                print("incorrect password")
                                exit(1)
                        else:
                            print("incorrect username")
                            exit(1)
            else:
                print("The signature is not authentic!")
                exit(1)
    else:
        print("Server must be authenticated first. Please restart protocol.")
        exit(1)

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
