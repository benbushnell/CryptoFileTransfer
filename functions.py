import os

from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Util import Padding


# rsa_hybrid_encrypt msg is the part of the message that you wish to encrypt
def rsa_hybrid_encrypt(msg, publickey):
    aes_key = Random.get_random_bytes(32)
    RSAcipher = PKCS1_OAEP.new(publickey)
    enc_aes_key = RSAcipher.encrypt(aes_key)

    iv = Random.get_random_bytes(AES.block_size)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_full_msg = Padding.pad(msg, AES.block_size, style='pkcs7')
    hybrid_enc_msg = iv + aes_cipher.encrypt(padded_full_msg) + enc_aes_key
    return hybrid_enc_msg


# the enc_msg of the function assumes that the IV and ONLY the IV is before the encrypted sections
def rsa_hybrid_decrypt(enc_msg, privatekey):
    enc_aes_key = enc_msg[-256:]
    iv = enc_msg[:16]
    enc_msg_body = enc_msg[16:-256]
    pkcs_cipher = PKCS1_OAEP.new(privatekey)
    aes_key = pkcs_cipher.decrypt(enc_aes_key)

    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypt_msg = aes_cipher.decrypt(enc_msg_body)
    decrypt_msg = Padding.unpad(decrypt_msg, AES.block_size)
    return decrypt_msg


def is_timestamp_valid(current_time, other_time):
    if current_time - other_time > 120:
        return False
    return True

#TODO: server reset that is called every time the session is invalidated that resets current user id,
# and any other parameters that are temporarily set like whether the server validation step has occurred etc.
#
# verify_signature msg assumes length of message in the
# beginning separated from the rest of the message with a delimiter |

def verify_signature(msg, publickey):
    first_delim = msg.find("|".encode())
    msg_len = msg[:first_delim]
    msg_len = int(msg_len.decode())
    # removed length from msg
    msg = msg[first_delim + 1:]
    sighashmsg = msg[msg_len:]
    msg = msg[:msg_len]
    gen_hash = SHA256.new(msg)
    verifier = pss.new(publickey)
    try:
        verifier.verify(gen_hash, sighashmsg)
        return True, msg
    except(ValueError, TypeError) as e:
        print(e)
        return False, ""


def get_filename(filepath):
    return os.path.basename(filepath)
