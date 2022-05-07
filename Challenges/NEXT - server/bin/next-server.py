import socketserver
import signal
import os
import pandas as pd
import numpy as np

L2CONSTRAIN = 5.6789
LINFCONSTRAIN = 1.234
CONFIDENCE = 0.8

def RL(x):
    return np.maximum(x, 0)

def SM(x):
    return np.array(np.exp(x) / np.sum(np.exp(x), axis=1))

def AB(x):
    x = np.matrix(x)
    return np.c_[np.ones((x.shape[0], 1)), x]

class ANN:
    def __init__(self, un):
        self.un = un
        self.LN = len(un)
        self.w = [0]
        self.Z = [0]
        self.A = [0]

    def FP(self):
        for i in range(1, self.LN - 1):
            self.Z.append(AB(self.A[-1]) * self.w[i])
            self.A.append(RL(self.Z[-1]))
        self.Z.append(AB(self.A[-1]) * self.w[-1])
        self.A.append(SM(self.Z[-1]))

    def PRED(self, X):
        self.Z[0] = np.matrix(X)
        self.A[0] = np.matrix(X)
        self.FP()
        return np.array(self.A[-1])

    def LOAD(self, fileName):
        f = open(fileName, "rb")
        wt = np.frombuffer(f.read(), np.float64)
        f.close()
        for i in range(1, len(self.un)):
            data = wt[: (self.un[i - 1] + 1) * self.un[i]]
            shape = (self.un[i - 1] + 1, self.un[i])
            self.w.append(np.matrix(data).reshape(shape))
            wt = wt[(self.un[i - 1] + 1) * self.un[i]:]

class Server(socketserver.BaseRequestHandler):
    def _recv(self):
        # recvline until enter
        msg = b''
        while True:
            try:
                abyte = self.request.recv(1)
                if abyte == b'\n':
                    break
                else:
                    msg += abyte
            except:
                break
        return msg.decode()

    def _send(self, msg, newline=True):
        try:
            if isinstance(msg , bytes):
                if newline:
                    msg += b'\n'
            else:
                if newline:
                    msg += '\n'
                msg = msg.encode()
            self.request.sendall(msg)
        except:
            pass

    def handle(self):
        signal.alarm(600)
        try:
            un = [784, 512, 256, 10]
            myNN = ANN(un)
            myNN.LOAD("weight.dat")
            data = pd.read_csv(r'picData.csv')
            X = np.matrix(data.iloc[:, 1:])
            mask = []
            for i in range(8):
                self._send(">> Mask " + str(i + 1) + " :")
                maskTemp = []
                for j in range(784):
                    print(i, j)
                    maskTemp.append(float(self._recv()))
                mask.append(np.array(maskTemp, dtype=np.float32).ravel())
            mask = np.matrix(mask)
            l2 = np.sum(np.linalg.norm(np.array(mask), axis=1)) / 8
            linf = np.max(np.linalg.norm(np.array(mask), ord=np.inf, axis=1))
            if l2 > L2CONSTRAIN:
                self._send("Huge L2 " + str(l2))
                return
            if linf > LINFCONSTRAIN:
                self._send("Huge Linf" + str(linf))
                return
            res = myNN.PRED(X + mask)
            for i in range(8):
                lable = np.argmax(res[i])
                if lable != i + 1:
                    self._send("Wrong Lable " + str(lable) + ", " + str(i + 1))
                    return
                if res[i][lable] < CONFIDENCE:
                    self._send("Unconfident " + str(lable) + ", " + str(i + 1) + ", " + str(res[i][lable]))
                    return
            # flag = os.getenv('FLAG')
            self._send("Thank you for saving Kyr, he told me to give this secret gift to you as his reward\n" + "flag{test}")
        except:
            pass

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == '__main__':
    HOST, PORT = '0.0.0.0', 10001
    server = ForkedServer((HOST, PORT), Server)
    server.allow_reuse_address = True
    server.serve_forever()