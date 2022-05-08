from Crypto.Util.number import *
from secret import flag
import random

assert flag[:9] == b'miniLCTF{'
assert flag[-1:] == b'}'
flag = flag[9:-1]
table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz!_@#$%^&"
flag = b'#' + flag + b'#' 
for i in range((64-len(flag)) % 64):
    flag += bytes([random.choice(table)]) 
p = getPrime(256)
members = [
    "deebato","noah","innerspace","wanan","tr4ck",
    "lacanva","4va10n","Cyxq","blackbird","humour",
    "scardow","kiriota",
    "Reverier","ling","eqqie","Cor1e","shal10w",
    "Ga1@xy","blackw4tch","luoq1an","arttnba3","cdcq",
    "la0t0ng",
    "Frank","Reclu3e","s@dmess","Happy",
    "zkonge","Endcat","Fl@g","Wal1et",
    "w1nd","flight","koocola","huai","v0idred",
    "fa1con"
]

my_sec = [bytes_to_long(flag[i*4:i*4+4]) for i in range(16)]

n = 32
t = 31

class Sharing:
    def __init__(self,secret):
        self.A = secret
        self.init_func()

    def init_func(self):
        for i in range(n - 16):
            self.A.append(random.randrange(1,1<<32))
    
    def f(self,x):
        ret = 0
        tmp = 1
        for i in range(n):
            ret += self.A[i] * tmp
            tmp *= x
        return ret % p

def get_msg(name,SS):
    inp = bytes_to_long(name)
    cip = SS.f(inp)
    return name,cip

def main():
    SS = Sharing(my_sec)
    f = open("./outputs",'wb')
    f.write(b"p " + str(p).encode() + b"\n")
    for i in range(t):
        tmp_member = random.choice(members)
        members.remove(tmp_member)
        name , cipher = get_msg(tmp_member.encode(),SS)
        f.write(name + b" " + str(cipher).encode() + b"\n")
    f.close()

main() 
