#!/usr/bin/env python3
# sender.py

import os, sys, getopt, time, json
import shutil
from getpass import getpass
from pathlib import Path

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from Crypto.Signature import pss
from Crypto.Util import Padding
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

import os,sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

import functions
from netinterface import network_interface

NET_PATH = './'
OWN_ADDR = 'S'
CLIENT = 'A'
user_auth_public_key = None
user_enc_public_key = None
user_path_dic = {"ben": "",
  "kevin": "",
  "michelle": "",
  "conrad": "",
  "levente": ""}
uid = None
USER_PATH = None
passphrase = None

# ------------       
# main program
# ------------
netif = network_interface(NET_PATH, OWN_ADDR)
serverauth = False
valid_headers_protocol_3 = ["NON_FILE_OP_NO_ARG", "NON_FILE_OP_ARG", "UPLOAD"]


SERVER_MACHINE_PATH = os.path.join(os.getcwd(), 'server_machine')
for user in user_path_dic.keys():
    addr_dir = os.path.join(SERVER_MACHINE_PATH, user)
    if not os.path.exists(addr_dir):
        os.mkdir(addr_dir)
    user_path_dic[user] = addr_dir

print('Server has been successfully set up.')

while True:
    # ----------------------------
    # ------ PROTOCOL PT 1 -------
    # ----------------------------
    print("Starting")

    # Calling receive_msg() in blocking mode ...
    status, msg = netif.receive_msg(blocking=True)  # when returns, status is True and msg contains a message
    if status:
        header = msg[:msg.find('|'.encode())]
        print(header.decode())
    if header.decode() == 'SERVER_AUTH':
        passphrase = getpass('Server key passphrase: ')
        server_auth_privatekey = RSA.import_key(open('server_keys/server_auth_privatekey.pem').read(), passphrase=passphrase)
        server_enc_privatekey = RSA.import_key(open('server_keys/server_enc_privatekey.pem').read(), passphrase=passphrase)
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
        serverauth = True
        # TODO: figure out why this fixes an error where the first instance of receive_msg is not blocking
        status, msg = netif.receive_msg(blocking=False)

    # ----------------------------
    # ------ PROTOCOL PT 2 -------
    # ----------------------------

    status, msg = netif.receive_msg(blocking=True)
    print(serverauth)
    if serverauth:
        if status:
            header = msg[:msg.find('|'.encode())]
            print(header.decode())
            if header.decode() == 'USER_AUTH':
                server_auth_privatekey = RSA.import_key(open('server_keys/server_auth_privatekey.pem').read(), passphrase)
                server_enc_privatekey = RSA.import_key(open('server_keys/server_enc_privatekey.pem').read(), passphrase)
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
                        error_msg = functions.error_msg("Timestamp error",user_enc_public_key, server_auth_privatekey)

                        netif.send_msg(CLIENT, error_msg)
                        status, msg = netif.receive_msg(blocking=False)
                        serverauth = False
                        continue
                    else:
                        with open('server_machine/info.json') as json_file:
                            data = json.load(json_file)
                            # check the user ID exists
                            valid_header = "VALID|".encode()
                            if pwmsg_parts[0].decode() in data:
                                # check password
                                if pwd_hash.hexdigest() == data[uid.decode()].lower():
                                    # Generate symmetric key (K_us) with scrypt
                                    salt = get_random_bytes(16)
                                    session_key = scrypt(pwmsg_parts[1].decode(), salt, 16, N=2**14, r=8, p=1)
                                    # generate a timestamp
                                    t = str(time.time()).encode()
                                    msg_symm = session_key + t
                                    # hash message
                                    hash_msg_symm = SHA256.new(msg_symm)
                                    # sign the hash
                                    sig_hash_msg_symm = pss.new(server_auth_privatekey).sign(hash_msg_symm)
                                    # concat signed hash to message
                                    final_msg = (str(len(msg_symm)) + "|").encode() + msg_symm + sig_hash_msg_symm

                                    #encrypt message
                                    enc_full_msg = functions.rsa_hybrid_encrypt(final_msg, user_enc_public_key)

                                    netif.send_msg(CLIENT, valid_header + enc_full_msg)
                                else:
                                    print("incorrect password--")
                                    # TODO send error message to client
                                    error_msg = functions.error_msg("Incorrect Login", server_auth_privatekey, user_enc_public_key)

                                    netif.send_msg(CLIENT, error_msg)
                                    status, msg = netif.receive_msg(blocking=False)
                                    serverauth = False
                                    continue

                            else:
                                print("incorrect username")

                                error_msg = functions.error_msg("Incorrect Login", server_auth_privatekey, user_enc_public_key)

                                netif.send_msg(CLIENT, error_msg)
                                status, msg = netif.receive_msg(blocking=False)
                                serverauth = False
                                continue
                else:
                    print("The signature is not authentic!")
                    error_msg = functions.error_msg("Incorrect Login", server_auth_privatekey, user_enc_public_key)

                    netif.send_msg(CLIENT, error_msg)
                    status, msg = netif.receive_msg(blocking=False)
                    serverauth = False
                    continue
        else:
            print("Server must be authenticated first. Please restart protocol.")
            error_msg = functions.error_msg("Server must be authenticated first. Please restart protocol.", server_auth_privatekey, user_enc_public_key)

            netif.send_msg(CLIENT, error_msg)
            status, msg = netif.receive_msg(blocking=False)
            serverauth = False

    # ----------------------------
    # ------ PROTOCOL PT 3 -------
    # ----------------------------

    # path to user directory
    USER_PATH = user_path_dic.get(uid.decode())
    cipher_protocol_3 = AES.new(session_key, AES.MODE_GCM)


    def change_dir(f):
        try:
            os.chdir(os.path.join(USER_PATH, f))
            print("Changed to directory {0}.".format(
                os.path.basename(os.getcwd())))
            msg_txt, msg_mac = cipher_protocol_3.encrypt_and_digest((str(time.time()) + "|" + "Changed to directory {0}.".format(
                os.path.basename(os.getcwd()))).encode())
            msg_3 = "SUCCESS|".encode() + cipher_protocol_3.nonce + ciphertext + mac_tag
            netif.send_msg(CLIENT, msg_3)
        except Exception as e:
            msg_txt, msg_mac = cipher_protocol_3.encrypt_and_digest(
                (str(time.time()) + "|" + str(e)).encode())
            msg_3 = "FAILURE|".encode() + cipher_protocol_3.nonce + ciphertext + mac_tag
            netif.send_msg(CLIENT, msg_3)


    def make_dir(f):
        try:
            os.mkdir(os.path.join(USER_PATH, f))
            print("Directory {0} created on server.".format(f))
            msg_txt, msg_mac = cipher_protocol_3.encrypt_and_digest(
                (str(time.time()) + "|" + "Directory {0} created on server.".format(f)).encode())
            msg_3 = "SUCCESS|".encode() + cipher_protocol_3.nonce + ciphertext + mac_tag
            netif.send_msg(CLIENT, msg_3)
        except Exception as e:
            msg_txt, msg_mac = cipher_protocol_3.encrypt_and_digest(
                (str(time.time()) + "|" + str(e)).encode())
            msg_3 = "FAILURE|".encode() + cipher_protocol_3.nonce + ciphertext + mac_tag
            netif.send_msg(CLIENT, msg_3)


    def remove_dir(f):
        try:
            os.rmdir(os.path.join(USER_PATH, f))
            print("Directory {0} successfully removed.".format(f))
            msg_txt, msg_mac = cipher_protocol_3.encrypt_and_digest(
                (str(time.time()) + "|" + "Directory {0} successfully removed.".format(f)).encode())
            msg_3 = "SUCCESS|".encode() + cipher_protocol_3.nonce + ciphertext + mac_tag
            netif.send_msg(CLIENT, msg_3)
        except Exception as e:
            msg_txt, msg_mac = cipher_protocol_3.encrypt_and_digest(
                (str(time.time()) + "|" + str(e)).encode())
            msg_3 = "FAILURE|".encode() + cipher_protocol_3.nonce + ciphertext + mac_tag
            netif.send_msg(CLIENT, msg_3)


    def download_f(f):
        try:
            # path to folder that server stores the file
            cur_dir = os.getcwd()
            src = os.path.join(cur_dir, f)
            dst = 'path/to/dest_dir'
            shutil.copy2(src, dst)
        except Exception as e:
            raise e

    # cant remove rn if file is in a folder
    def remove_f(f):
        try:
            file = os.path.join(USER_PATH, f)
            os.remove(file)
        except Exception as e:
            raise e


    def print_dir_name():
        # print(user_root_dir)
        print("Current working directory: {0}".format(
            os.path.basename(os.getcwd())))
        msg_txt, msg_mac = cipher_protocol_3.encrypt_and_digest(
            (str(time.time()) + "|" + "Current working directory: {0}".format(
            os.path.basename(os.getcwd()))).encode())
        msg_3 = "SUCCESS|".encode() + cipher_protocol_3.nonce + ciphertext + mac_tag
        netif.send_msg(CLIENT, msg_3)

    def print_dir_content():
        with os.scandir(os.getcwd()) as entries:
            for entry in entries:
                if entry.name[0] not in ('.', '_'):
                    print(entry.name)



#Todo: Prevent user from moving outside of their own folder.

    def non_file_op(operation, argument):
        if argument is not None:
            if operation == 'CWD':
                change_dir(argument)
            elif operation == 'MKD':
                make_dir(argument)
            elif operation == 'RMD':
                remove_dir(argument)
            elif operation == 'DNl':
                NotImplemented
            elif operation == 'RMF':
                remove_f(argument)
        else:
            if operation == 'GWD':
                print_dir_name()
            elif operation == 'LST':
                print_dir_content()



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
        status, msg = netif.receive_msg(blocking=True)
        if status:
            #grab header
            header = msg[:msg.find('|'.encode())].decode()
            #remove header
            msg = msg[msg.find('|'.encode()) + 1:]
            #check header
            if header not in valid_headers_protocol_3:
                print("eat my ass")
                #TODO: Invalid header error
            else:
                # msg format: Nonce (16 bytes) + Ciphertext + MacTag (16 bytes)
                nonce = msg[:16]
                mac_tag = msg[-16:]
                ciphertext = msg[16:-16]
                cipher = AES.new(session_key, AES.MODE_GCM, nonce)
            try:
                plaintext = cipher.decrypt_and_verify(ciphertext, mac_tag)
            except (ValueError, KeyError):
                print("Invalid Decryption")
                # TODO: Error Handling
            if header == "NON_FILE_OP_NO_ARG":
                # plaintext format: Ts | operation
                ts = float(plaintext[:-3].decode())
                operation = plaintext[-3:].decode()
                if functions.is_timestamp_valid(time.time(), ts):
                    non_file_op(operation, None)
                else:
                    print("Timestamp Error")
                    #Todo: Timestamp error
            elif header == "NON_FILE_OP_ARG":
                # plaintext format: Ts | operation + argument
                delim_pos = plaintext.find("|".encode())
                ts = float(plaintext[:delim_pos].decode())
                operation = plaintext[delim_pos + 1: delim_pos + 4]
                argument = plaintext[delim_pos + 4:]
                if functions.is_timestamp_valid(time.time(), ts):
                    non_file_op(operation, argument)
                else:
                    print("Timestamp Error")
                    #TODO: Timestamp Error
            elif header == "UPLOAD":
                # plaintext format: Ts | file
                delim_pos = plaintext.find("|".encode())
                ts = float(plaintext[:delim_pos].decode())
                file = plaintext[delim_pos + 1:]
                if functions.is_timestamp_valid(time.time(), ts):
                    print("do this")
                    #Todo: put the file into the directory
                else:
                    print("Timestamp Error")
                    #TODO: Timestamp Error



        msg = input('Type a message: ')
        dst = input('Type a destination address: ')

        netif.send_msg(dst, msg.encode('utf-8'))

        if input('Continue? (y/n): ') == 'n': break
