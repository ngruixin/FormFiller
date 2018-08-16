# adapted from https://gist.github.com/crmccreary/5610068
from Crypto.Cipher import AES
from Crypto import Random
import binascii
import secrets
import hashlib
from Crypto.Protocol.KDF import PBKDF2
import hmac

# pads and unpads using PKCS7 algorithm 
pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size) 
unpad = lambda s : s[0:-s[-1]]

def genKey(pwd, salt):
    '''
    Generates a secret key (length 32 bytes) using the password 
    extension protocol PBKDF2 with 1000 iterations.
    '''
    return PBKDF2(pwd, salt, 32, 1000)

def genSalt():
    '''
    Generates a random salt of length 16 bytes
    '''
    return secrets.token_hex(16)

def saltAndHash(salt, pwd):
    '''
    Returns a hex value of the salted and hashed password 
    '''
    return hashlib.sha256((pwd+salt).encode()).hexdigest()

def sha256(s):
    '''
    Returns a hex encoded value of sha256(@s)
    '''
    return hashlib.sha256(s.encode()).hexdigest()

def mac(msg, key):
    '''
    Performs a hmac on @msg using @key and sha256 algorithm. 
    Returns a hex encoded value.
    '''
    return hmac.new(key, str.encode(msg), hashlib.sha256).hexdigest()

def encrypt(raw, key):
    '''
    Encrypts @raw using @key with AES-CBC mode and stores the iv 
    in the first 16 bytes 
    Returns the hex encoded value
    '''
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    hex_string = binascii.hexlify(iv + cipher.encrypt(raw)).decode('utf-8')
    return hex_string

def decrypt(enc, key):
    '''
    Decodes @enc using the iv stores in the first 16 bytes. 
    Uses AES-CBC mode for decryption.
    '''
    enc = enc.encode('utf-8')
    enc = binascii.unhexlify(enc)
    iv = enc[:16]
    enc = enc[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc)).decode('utf-8')



    
