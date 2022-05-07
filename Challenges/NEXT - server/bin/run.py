#!/usr/bin/python
# -*- coding:utf8 -
import pandas as pd
import numpy as np
import base64

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

class ANN: # do you know ANN ?
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

def ENC(ans: np.matrix):
    if ans.shape != (1, 784):
        return "wat r u doin?"
    return base64.b64encode(ans.tobytes()).decode().replace('\n', '')

def DEC(ans: bytes):
    print(ans)
    print(len(ans))
    buffer = base64.b64decode(ans)
    buffer = np.frombuffer(buffer, dtype=np.float64, count=784)
    return np.array(buffer)

def CHECK(ans: np.matrix, myNN: ANN, X):
    l2 = np.sum(np.linalg.norm(np.array(ans), axis=1)) / 8
    linf = np.max(np.linalg.norm(np.array(ans), ord=np.inf, axis=1))
    if l2 > L2CONSTRAIN:
        print("Huge L2 " + str(l2))
        return
    if linf > LINFCONSTRAIN:
        print("Huge Linf" + str(linf))
        return
    res = myNN.PRED(X + mask)
    for i in range(8):
        lable = np.argmax(res[i])
        if lable != i + 2:
            print("Wrong Lable " + str(lable) + ", " + str(i + 2))
            return
        if res[i][lable] < CONFIDENCE:
            print("Unconfident " + str(lable) + ", " + str(i + 2) + ", " + str(res[i][lable]))
            return
    print("A precise and efficient attack, well done m8\nHere's your reward, congratulations\nminiLCTF\{m33t-L2-T4rgeted-477ACK\}")

if __name__ == '__main__':
    un = [784, 512, 256, 10]
    myNN = ANN(un)
    myNN.LOAD("weight.dat")
    data = pd.read_csv(r'picData.csv')
    X = np.matrix(data.iloc[:, 1:])
    mask = []
    for i in range(8):
        IN = input(">> Mask " + str(i + 1) + " :\n")
        mask.append(DEC(IN.encode()))
    mask = np.matrix(mask)
    CHECK(mask, myNN, X)