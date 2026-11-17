# Planted weak crypto, so qscan has something to find. Do not copy this code.
import hashlib

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA


def fingerprint(data):
    return hashlib.md5(data).hexdigest()          # MD5: broken today


def make_keys():
    return RSA.generate(2048)                     # RSA: quantum-vulnerable


def encrypt(key, block):
    return AES.new(key, AES.MODE_ECB).encrypt(block)   # AES-ECB: broken today


def good_hash(data):
    return hashlib.sha256(data).hexdigest()       # fine, not reported
