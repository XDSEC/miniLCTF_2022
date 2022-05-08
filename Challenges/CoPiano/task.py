from Crypto.Util.number import *
import os
from flag import flag

nbit = 2048
p, q = getPrime(nbit // 2), getPrime(nbit // 2)
N = p * q
e = 3
cipher_block_length = nbit // 8
plain_block_length = cipher_block_length // 8

def pad(msg):
    return msg + ((plain_block_length - len(msg) % plain_block_length) % plain_block_length) * b'\x00'

def block_enc(msg):
    m = bytes_to_long(msg)
    x = bytes_to_long(os.urandom(plain_block_length))

    c = long_to_bytes(pow(m ^ x, e, N)).rjust(cipher_block_length,b'\x00')
    t = m & x
    return c , (x,t)

def ecb_mode_enc(msg):
    plain_block = [msg[plain_block_length * i: plain_block_length * (i + 1)] for i in range(len(msg) // plain_block_length)]
    cipher_text = b''
    x_list = []
    t_list = []
    for msg_part in plain_block:
        cipher_part , (x_tmp,t_tmp) = block_enc(msg_part)
        cipher_text += cipher_part
        x_list.append(x_tmp)
        t_list.append(t_tmp)
    return cipher_text , x_list , t_list

cipher , x_list, t_list = ecb_mode_enc(pad(flag))

f = open("./output",'wb')
f.write(b"N =" + str(N).encode() + b'\n')
f.write(b"e =" + str(e).encode() + b'\n')
f.write(b"c =" + cipher + b'\n')
f.write(b"x_list =" +str(x_list).encode() + b'\n')
f.write(b"t_list =" +str(t_list).encode() + b'\n')
f.close() 
