#!/usr/bin/env python3
# sender.py

import os, sys, getopt, time
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from Crypto.Util import Padding
import os, sys, inspect

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
user_private_file_key = None

# ----------------------------
# ------ PROTOCOL PT 1 -------
# ----------------------------
# getting server publickey
server_auth_publickey = RSA.import_key(open('server_keys/server_auth_publickey.pem').read())
server_enc_publickey = RSA.import_key(open('server_keys/server_enc_publickey.pem').read())

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
        ciphertext, mac_tag = cipher_protocol_3.encrypt_and_digest((str(time.time()) + "|" + operation).encode())
        msg_3 = "NON_FILE_OP_NO_ARG|".encode() + cipher_protocol_3.nonce + ciphertext + mac_tag
        netif.send_msg(SERVER, msg_3)
    else:
        ciphertext, mac_tag = cipher_protocol_3.encrypt_and_digest(
            (str(time.time()) + "|" + operation + argument).encode())
        msg_3 = "NON_FILE_OP_ARG|".encode() + cipher_protocol_3.nonce + ciphertext + mac_tag
        netif.send_msg(SERVER, msg_3)


def upload(filepath):
    print('Performing upload...')
    try:
        f = open(filepath, "rb").read()
        if user_private_file_key == None:
            get_user_file_key()
        # AES-GCM cipher for file encryption
        aes_cipher_file = AES.new(user_private_file_key, AES.MODE_GCM)
        # Encrypt file
        file_ciphertext, mac = aes_cipher_file.encrypt_and_digest(f)
        # Nonce for file cipher, actual file ciphertext, and MAC for the file encryption
        enc_file = aes_cipher_file.nonce + file_ciphertext + mac
        # Encrypt timestamp along with the encrypted file using protocol encryption scheme
        ciphertext, mac_tag = cipher_protocol_3.encrypt_and_digest((str(time.time()) + "|").encode() + enc_file)
        msg_3 = "UPLOAD|".encode() + cipher_protocol_3.nonce + ciphertext + mac_tag
        netif.send_msg(SERVER, msg_3)
    except FileNotFoundError:
        print('Could not find file. Please try again.')
        return

def client_listen():
    print("listening" + str(time.time()))
    status, svr_msg = netif.receive_msg(blocking=True)
    print("listen has heard")
    #read header
    header = svr_msg[:svr_msg.find('|'.encode())].decode()
    # remove header
    svr_msg = svr_msg[svr_msg.find('|'.encode()) + 1:]
    nonce = svr_msg[:16]
    mac_tag = svr_msg[-16:]
    ciphertext = svr_msg[16:-16]
    cipher = AES.new(session_key, AES.MODE_GCM, nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, mac_tag)
    except (ValueError, KeyError):
        print("Invalid Decryption")
        # TODO: Should the client abort here?
        ("Invalid Decryption")
    ts = plaintext[:plaintext.find('|'.encode())].decode()
    msg_body = plaintext[plaintext.find('|'.encode()) + 1:].decode()
    if not functions.is_timestamp_valid(time.time(), float(ts)):
        print("Error: Terminating Connection.")
        #TODO: Put client termination func call here, kevin
    else:
        print("got and decrypted response")
        if header == "SUCCESS":
            print(msg_body)
        elif header == "FAILURE":
            print(msg_body)
        elif header == "DOWNLOAD":
            #TODO: handle file download once michelle is done with the server send file
            print("Do this")

def get_user_file_key():
    global user_private_file_key
    user_passphrase = getpass('Type file decryption passphrase. This will be stored for the session: ')
    salt = open('client_machine/client_private_symm_key_salt.pem', 'rb').read()
    user_private_file_key_temp = scrypt(user_passphrase, salt, 16, N=2 ** 14, r=8, p=1)
    # test with pre-encrypted file to ensure the passphrase is correct
    try:
        verif_file = open('client_machine/verification_file.pem', 'rb').read()
        nonce = verif_file[:16]
        ciphertext = verif_file[16:-16]
        mac = verif_file[-16:]
        test_cipher = AES.new(user_private_file_key_temp, AES.MODE_GCM, nonce=nonce)
        plaintext = test_cipher.decrypt_and_verify(ciphertext, mac)
        # assign the key if no error is thrown by the previous line
        user_private_file_key = user_private_file_key_temp
    except (ValueError, KeyError):
        print('Incorrect file passphrase. Terminating connection.')
        exit(1)


def decrypt_and_verify_mac(enc_msg):
    nonce = enc_msg[:16]
    mac = enc_msg[-16:]
    enc_msg = enc_msg[16:-16]

    cipher_portocol = AES.new(session_key, AES.MODE_GCM, nonce= nonce)
    try:
        msg = cipher_portocol.decrypt_and_verify(enc_msg, mac)
        print(msg.decode())
        return msg, True
    except (ValueError, KeyError) as e:
        return e, False


def opt_req_arg(opt):
    return opt.upper() in {'MKD', 'RMD', 'CWD', 'RMF'}


# SUCCESS
# FAILURE

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)
print('-------------------------------------')
print('----------Main loop started----------')
print('-------------------------------------')
print('Type \'help\' for available commands.')
while True:
    msg = input('Type a command: ')
    split = msg.split(' ')
    opt = split[0].strip().upper()
    arg = None
    if len(split) == 1:
        if opt == 'HELP':
            print('------------------------------------------------------------------------')
            print('CWD <folder name>: \t Change working directory to this folder')
            print('MKD <folder name>: \t Create a folder on the server')
            print('RMD <folder name>: \t Remove a folder from the server')
            print('UPL <file name>: \t Upload a file to the server')
            print('DNL <file name>: \t Download a file from the server')
            print('RMF <file name>: \t Remove a file from a folder on the server')
            print('GWD <none>: \t \t Print the name of the current working directory')
            print('LST <none>: \t \t List the content of a folder')
            print('------------------------------------------------------------------------')
        elif (opt == 'GWD') or (opt == 'LST'):
            non_file_op(opt, arg)
            client_listen()
        else:
            print('Invalid command. Try again.')
    elif len(split) == 2:
        arg = split[1]
        if opt == 'UPL':
            upload(arg)
            print('done with upload')
            client_listen()
        elif opt.upper() == 'DNL':
            #TODO handle downloads
            print("handle download")
            client_listen()
        elif opt_req_arg(opt):
            non_file_op(opt, arg)
            client_listen()

        else:
            print('Invalid command. Try again.')
    elif len(split) < 1:
        print('Too few arguments for this command, please try again.')
    else:
        print('Valid command. Try again.')
    cont_session = input('Perform another operation? (y/n): ')
    if cont_session.strip() == 'n': break