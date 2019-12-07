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

from netinterface import network_interface

NET_PATH = './'
OWN_ADDR = 'S'
CLIENT = 'A'
user_public_key = None

# ------------       
# main program
# ------------
netif = network_interface(NET_PATH, OWN_ADDR)
serverauthcode = 0
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
    user_public_key = RSA.import_key(key_and_nonce[:user_public_key_len])
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
    serverauthcode = 1
status, msg = netif.receive_msg(blocking=True)
if serverauthcode == 1:
    if status:
        header = msg[:msg.find('|'.encode())]
        if header.decode() == 'USER_AUTH':
            server_privatekey = RSA.import_key(open('server_keys/server_privatekey.pem').read())
            # decrypt symmetric key
            aes_key_enc = msg[-256:]
            pkcs_cipher = PKCS1_OAEP.new(server_privatekey)
            aes_key = pkcs_cipher.decrypt(aes_key_enc)
            # decrypt user's public key and nonce
            beginning_of_iv = msg.find('|'.encode()) + 1
            end_of_iv = msg.find('|'.encode()) + 1 + AES.block_size
            iv = msg[beginning_of_iv:end_of_iv]
            #Set up AES
            aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            #Extract meat of message
            msg = aes_cipher.decrypt(msg[end_of_iv:-256])
            msg = Padding.unpad(msg, AES.block_size)
            first_delim = msg.find("|".encode())
            pwmsg_len = msg[:first_delim]
            pwmsg_len = int(pwmsg_len.decode())
            msg = msg[first_delim + 1:]
            sighashpwmsg = msg[pwmsg_len:]
            pwmsg= msg[:pwmsg_len]
            server_hash = SHA256.new(pwmsg)
            verifier = pss.new(user_public_key)
            try:
                verifier.verify(server_hash, sighashpwmsg)
                print("The signature is authentic")
                pwmsg_parts = pwmsg.split("|".encode())
                uid = pwmsg_parts[0]
                ts = pwmsg_parts[2]
                pwd_hash = SHA256.new(pwmsg_parts[1])
                if time.time() - float(ts) > 120:
                    print("Timestamp error")
                    ##
                    ##
                    #Todo: Send user error message
                    ##
                    ##
                else:
                    with open('info.json') as json_file:
                        data = json.load(json_file)
                        # check the user ID exists
                        if pwmsg_parts[0].decode() in data:
                            # check password
                            if pwd_hash.hexdigest() == data[uid.decode()].lower():
                                # TODO: Remove this line, we're not logged in yet
                                print("logged in")
                                # Generate symmetric key (K_us) with scrypt
                                salt = get_random_bytes(16)
                                key = scrypt(pwmsg_parts[1].decode(), salt, 16, N=2**14, r=8, p=1)
                                # generate a timestamp
                                t = str(time.time()).encode()
                                msg_symm = key + t
                                # hash message
                                hash_msg_symm = SHA256.new(msg_symm)
                                sig_hash_msg_symm = pss.new(server_privatekey).sign(hash_msg_symm)
                                final_msg = msg_symm + "|".encode() + sig_hash_msg_symm
                                pkcs_cipher = PKCS1_OAEP.new(user_public_key)

                                #hybrid again
                                rand_key = Random.get_random_bytes(32)
                                new_iv = Random.get_random_bytes(AES.block_size)
                                new_aes_cipher = AES.new(rand_key, AES.MODE_CBC, new_iv)
                                padded_final_msg = Padding.pad(final_msg, AES.block_size, style='pkcs7')
                                to_client_msg = new_iv + new_aes_cipher.encrypt(padded_final_msg)

                                enc_rand_key = pkcs_cipher.encrypt(rand_key)
                                full_msg = to_client_msg + enc_rand_key
                                netif.send_msg(CLIENT, full_msg)


                            else:
                                print("incorrect password")
                                exit(1)
                        else:
                            print("incorrect username")
                            exit(1)
            except (ValueError, TypeError) as e:
                print(e)
                print("The signature is not authentic!")
                exit(1)


            # Create new IV and append to encrypted nonce and timestamp
            ''' new_iv = Random.get_random_bytes(AES.block_size)
            new_aes_cipher = AES.new(aes_key, AES.MODE_CBC, new_iv)
            padded_full_msg = Padding.pad(nonce_and_timestamp_msg, AES.block_size, style='pkcs7')
            to_client_msg = new_iv + new_aes_cipher.encrypt(padded_full_msg)
            netif.send_msg(CLIENT, to_client_msg)'''
    else:
        print("Server must be authenticated first. Please restart protocol.")

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
