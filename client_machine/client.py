#!/usr/bin/env python3
# sender.py

import os, sys, getopt, time
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from Crypto.Util import Padding
import os,sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)
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

user_auth_keys = RSA.generate(2048)
user_enc_keys = RSA.generate(2048)
session_key = None

# ----------------------------
# ------ PROTOCOL PT 1 -------
# ----------------------------
# getting server publickey
server_auth_publickey = RSA.import_key(open('../server_keys/server_auth_publickey.pem').read())
server_enc_publickey = RSA.import_key(open('../server_keys/server_enc_publickey.pem').read())

user_auth_publickey = user_auth_keys.publickey().export_key()
user_auth_privatekey = user_auth_keys.export_key()

user_enc_publickey = user_enc_keys.publickey().export_key()
user_enc_privatekey = user_enc_keys.export_key()

# 256 bit random nonce
nonce = Random.get_random_bytes(32)

# saving this to verify against server timestamp
t = time.time()

# create message to be encrypted
msg = user_auth_publickey + user_enc_publickey + nonce
enc_msg = functions.rsa_hybrid_encrypt(msg, server_enc_publickey)

msg_header = 'SERVER_AUTH'.encode() + '|'.encode()

full_msg = msg_header + enc_msg

netif.send_msg(SERVER, full_msg)

# wait for response
status, svr_msg = netif.receive_msg(blocking=True)

msg_received = functions.rsa_hybrid_decrypt(svr_msg, user_enc_keys)

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

##TODO: Garbage collect password
password = getpass("Enter Password: ")

pwmsg = uid + "|" + password + "|" + str(time.time())
msglen = str(len(pwmsg))

# RSA PSS protocol for signature
hashpwdmsg = SHA256.new(pwmsg.encode())
print(type(hashpwdmsg))
sigpwdmsg = pss.new(user_auth_keys).sign(hashpwdmsg)

# Building the message
msg_header = 'USER_AUTH'.encode() + '|'.encode()
enc_msg = functions.rsa_hybrid_encrypt((msglen + "|" + pwmsg).encode() + sigpwdmsg, server_enc_publickey)

full_msg = msg_header + enc_msg

# Sending the message
netif.send_msg(SERVER, full_msg)

# Listening for response
status, svr_msg = netif.receive_msg(blocking=True)

# checking header
header = svr_msg[:svr_msg.find('|'.encode())]
# remove header
svr_msg = svr_msg[svr_msg.find('|'.encode()) + 1:]

# Decrypt message body
print(header.decode())
msg_received = functions.rsa_hybrid_decrypt(svr_msg, user_enc_keys)

# chop off the key so that we don't find an early delimiter
sig_verified, msg_key = functions.verify_signature(msg_received, server_auth_publickey)

if sig_verified:
    print("The signature is authentic")
else:
    print("The signature is not authentic!")
    exit(1)

if header.decode() == "ERR":

    if not functions.is_timestamp_valid(time.time(), float(msg_key[msg_key.find("|".encode())+1:])):
        print("Terminating connection request.")
    else:
        msg = msg_key[:msg_key.find("|".encode())]
        print(msg.decode())
    exit(1)
elif header.decode() == "VALID":
    if not functions.is_timestamp_valid(time.time(), float(msg_key[16:])):
        print("Terminating connection request.")
        exit(1)
    else:
        session_key = msg_key[:16]
        print("Logged in, session key retrieved")


    status, svr_msg = netif.receive_msg(blocking=False)

'''
----------------------------
------ PROTOCOL PT 3 -------
----------------------------
'''

cipher_protocol_3 = AES.new(session_key, AES.MODE_GCM)


def non_file_op(operation, argument):
    print('Performing operation...')
    if argument is None:
        ciphertext, mac_tag = cipher_protocol_3.encrypt_and_digest((str(time.time()) + operation).encode())
        msg_3 = "NON_FILE_OP_NO_ARG|".encode() + cipher_protocol_3.nonce + ciphertext + mac_tag
        netif.send_msg(SERVER, msg_3)
        status, msg = netif.receive_msg(blocking=True)
        print(msg)
    else:
        ciphertext, mac_tag = cipher_protocol_3.encrypt_and_digest((str(time.time()) + "|" + operation + argument).encode())
        msg_3 = "NON_FILE_OP_ARG|".encode() + cipher_protocol_3.nonce + ciphertext + mac_tag
        netif.send_msg(SERVER, msg_3)
        status, msg = netif.receive_msg(blocking=True)
        print(msg)


def upload(filepath):
    print('Performing upload...')
    try:
        f = open(filepath, "rb")
    except FileNotFoundError:
        print('Could not find file. Please try again.')
        return
    ciphertext, mac_tag = cipher_protocol_3.encrypt_and_digest((str(time.time()) + "|").encode() + f.read())
    msg_3 = "UPLOAD|".encode() + cipher_protocol_3.nonce + ciphertext + mac_tag
    netif.send_msg(SERVER, msg_3)


def opt_req_arg(opt):
    return opt.upper() in {'MKD', 'RMD', 'CWD', 'DNL', 'RMF'}

# SUCCESS
# FAILURE

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)
print('Main loop started...')
while True:
    msg = input('Type a command: ')
    split = msg.split(' ')
    if len(split) == 2:
        opt = split[0]
        arg = split[1]
        if opt.upper() == 'UPL':
            upload(arg)
        elif opt_req_arg(opt):
            non_file_op(opt, arg)
        else:
            print('Too many arguments for this command, please try again.')
    elif len(split) > 2:
        print('Incorrect format, cannot complete operation.')
    else:
        if not opt_req_arg(split[0]):
            non_file_op(split[0], None)
        else:
            print('Too few arguments for this command, please try again.')

    if input('Perform another operation? (y/n): ') == 'n': break
