from Crypto.Util.number import*
from secret import flag
from hashlib import sha256
import socketserver
import signal
import string
import random
table = string.ascii_letters+string.digits

def get_key():
    tmp = random.randrange(1,1<<27)
    while 1:
        tmp += 2
        if isPrime(tmp):
            break
    d = tmp * p
    e = inverse(d,phi)
    return d,e

p = getPrime(512)
q = getPrime(512)
n = p * q
phi = (p-1) * (q-1)
d,e = get_key()
msg = getRandomRange(1,1<<400)
c = pow(msg,e,n)


class Task(socketserver.BaseRequestHandler):
    def _recvall(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def send(self, msg, newline=True):
        try:
            if newline:
                msg += b'\n'
            self.request.sendall(msg)
        except:
            pass

    def recv(self, prompt=b''):
        self.send(prompt, newline=False)
        return self._recvall()

    def proof_of_work(self):
        proof = (''.join([random.choice(table)for _ in range(20)])).encode()
        sha = sha256(proof).hexdigest().encode()
        self.send(b"[+] sha256(XXXX+" + proof[4:] + b") == " + sha )
        XXXX = self.recv(prompt = b'[+] Plz Tell Me XXXX :')
        if len(XXXX) != 4 or sha256(XXXX + proof[4:]).hexdigest().encode() != sha:
            return False
        return sha.decode()

    def handle(self):
        Hash = self.proof_of_work()
        if not Hash:
            self.request.close()
        self.send(b"\nI'll send you my encrypt data.Can you decrypt it in 5mins???")
        self.send(b'e = ' + hex(e).encode())
        self.send(b'n = ' + hex(n).encode())
        self.send(b'c = ' + hex(c).encode())
        signal.alarm(300)
        self.send(b'plz response the msg:')
        sec_m = int(self.recv(),16)
        if sec_m == msg:
            self.send(b'\nYou win!Give you my flag!')
            self.send(flag)
        self.send(b"\nConnection has been closed  =.=  ")
        self.request.close()

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10001
    print("HOST:POST " + HOST+":" + str(PORT))
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
