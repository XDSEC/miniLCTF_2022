## Paralympics

在`scanType`循环`Increased value`和`Decreased value`大约能收敛到几百个结果

分析他们的Value可得，现在存储的大多是一些184或18.4左右的Value（184是低视角的坐标，如果是高视角则是218），基本可以确定184以及18.4的值才是与坐标相关的，去掉无关值并人力二分查找真正的坐标

但注意真坐标包含了Camera坐标和玩家实体的坐标，一般来说Camera作为玩家实体的一个子组件跟随玩家，而实际触发许多Trigger都是由玩家本体触发而非Camera，所以每次修改Value后应当回去看一下到底是改到了Camera坐标还是实体坐标，不管是改到了他们谁坐标，Camera都会在回到游戏进程时视角瞬移到实体位置，这并非我出题时候的本意，更多应该是因为UE4自己的优化机制导致的

确定Z坐标后（UE4使用右手坐标系），由于XYZ坐标通常是连续储存的，所以也就获取了XY坐标的地址，手动加一下就行

![img](https://kyriota.com/images/Other/miniL2022-Paralympics.png)

之后改一下坐标就好啦

## NEXT

**参考文献：[Towards Evaluating the Robustness](https://arxiv.org/abs/1608.04644)**

题目名为`NEXT`，顾名思义就是让你对MNIST中的几个Samples加扰动，使得如下的8个Samples被模型识别成其原本lable的下一个数，如1→2，2→3...

为了让题目有个情景，所以把原本的weight给轮了一下顺序，原lable本应是[0,1,2,3,4,5,6,7,8,9]，被改成了[1,2,3,4,5,6,7,8,9,0]，于是乎题目就有了一个虽然不合理但可以忽悠人的情景

![img](https://kyriota.com/images/L2TarAtt_Original.png)

模型为带DropOut的FCNN，虽然带DropOut，但是整体梯度比较明显，对扰动的鲁棒性欠佳，很适合作为攻击对象

源码上对原本的函数做了一点混淆，比如`softMax`缩写成`SM`之类的，主要是为了选手深入了解神经网络之后再入手题目，不要底层没摸清楚做纯纯的TFboy

限制了L2和Linf的大小，是为了让做题人明确这是一个L2 Attack

task中不包含`torch`，`TF`之类的，但可以把weight手动导入一下，然后使用如`tf.gradientTape`之类的方法自动求梯度，我自己解是用比较土的手搓`BackProp`

### Loss

参考论文，在`Loss`中包含了对L2的惩罚项，我implement的时候使用的是类似于参数正则化一样的方法，简单但有效，在每次迭代后：根据对L2的限制，让最终的噪声`Pert`自减一点点

而对于如何在`Loss`中体现出逼近Target，直接借鉴一下Carlini大神的结论，即参考文献中的`f6`，毕竟这些东西就是凭经验凭感觉弄出来的，他们基本也就是选了一些自己觉得有可能可行的`Loss`然后全部跑一遍，找一个效果最好的

![img](https://kyriota.com/images/L2TarAtt_f6.png)

其中加号上标表示对括号内的参数`x`执行`max(x, 0)`

大概意会一下，首先这玩意儿得从`logits`层开始回归，然后至于他这个`Loss`的思想也就字面意思：打压当前概率最高的，进而扶持target的概率（劫富济贫属于是

我没有完全按照他的`loss`来（主要是为了方便），但是思想都是一样的，我implement的就是一个对无关项置零的交叉熵，代码如下

```python
def d_crossEntPert(self):
    mat = np.matrix(self.A[-1] - self.y)
    if np.argmax(np.array(self.y).ravel()) != np.argmax(np.array(self.A[-1]).ravel()):
        for i in range(10):
            if i != np.argmax(np.array(self.y).ravel()) and i != np.argmax(np.array(self.A[-1]).ravel()):
                mat[0, i] = 0
	return mat
```

注1：此处的`Loss`还并非最终形态，因为没有加入对`Pert`的惩罚项

注2：关于为什么要在最终label是target的情况下直接return，则是因为这样在已经找到属于target的决策区域后的下降速度更快，还可以防止梯度消失

### Get Gradient

由于是自己搓的FCNN，获取梯度直接`backProp`就行了，比如想要倒数第二层的dZ，`backProp`之后就直接`FCNN.dZ[-2]`，非常方便，这个手搓`BP`的梯度也拿去和`tensorflow`中的`gradientTape`求出的梯度做了对比，保证梯度正确

简化剔除了一些常规`BP`在此情境下不需要的内容，得到以下代码

```python
def backProp(self, d_lossFunc):
    self.dZ[-1] = d_lossFunc()
    dw = self.A[-2].T * self.dZ[-1]
    db = np.sum(self.dZ[-1], axis=0)
    self.dw[-1] = np.r_[db, dw]
    for i in reversed(range(1, self.layerNum - 1)):
        self.dA[i] = RemoveBias(self.dZ[i + 1] * self.w[i + 1].T)
        self.dZ[i] = np.multiply(d_relu(self.Z[i]), self.dA[i])
        dw = self.A[i - 1].T * self.dZ[i]
        db = np.sum(self.dZ[i], axis=0)
        self.dw[i] = np.r_[db, dw]
	self.dA[0] = RemoveBias(self.dZ[1] * self.w[1].T)
	self.dZ[0] = self.dA[0]
```

### Fool

现在关键成分都已经齐全了，就可以开始生成AdversarialPerturbation了

基本的迭代过程大致如下：

* 把target设置成`y`，因为`loss`函数中会用到（比如要把`6`糊弄成`7`，则`target=7`）
* ForwardProp()
* 判断target的confidence是否符合要求，符合则return，不符合则继续
* BackProp()
* 对梯度加入关于`Pert`的惩罚项

在此基础上，还进行了几点优化：

* 因为这个方法肉眼可见的容易出现惩罚项与逼近Target的方向相反的情况，所以加入了一个在Stuck时进行随机扰动的功能
* 对起点进行比较小的随机扰动，稍微差异化每次下降过程

（在输出中加emoji主要是为了快速浏览运行结果，而且事实证明Jupyter对此支持是没问题的，看着很酥糊

```python
class Fool:
    def __init__(self, myNetwork):
        self.Network = myNetwork

    def GetGrad(self, X):
        pred = self.Network.predict(X)
        self.Network.backProp(self.Network.d_crossEntPert)
        return self.Network.dA[0], pred.ravel()

    def Fool(self, X, y, tar, foolRate=0.5, maxIter=500, step=0.05, minGrad=0.05, maxGrad=10,
             constrain=10, stuckRandL2=1, initRandL2=1):
        rand = np.matrix(np.random.randn(1, 784))
        pert = np.zeros((1, 784)) + initRandL2 * rand / np.linalg.norm(rand)
        loss = []
        L2Rec = []
        cnt = 0
        stuckCnt = 0
        stuckJudgeCnt = 0
        success = False
        self.Network.predict(X + pert)
        print("init: " + str(y) + " prob: " +
              str(self.Network.A[-1].ravel()[y]))
        self.Network.y = OneHot(
            1, self.Network.unitNum[-1], y) if tar == -1 else OneHot(1, self.Network.unitNum[-1], tar)
        while(True):
            print("\rcnt: " + str(cnt) + "  stuck: " + str(stuckCnt), end='')
            grad, pred = self.GetGrad(X + pert)
            loss.append(np.linalg.norm(self.Network.A[-1]) if tar == -1 else
                        -np.sum(np.array(self.Network.y) * np.log(self.Network.A[-1])
                        + np.array(1 - self.Network.y) * np.log(1 - self.Network.A[-1])))
            if ((self.Network.A[-1].ravel()[y] < foolRate if tar == -1 else self.Network.A[-1].ravel()[tar] > foolRate)
                    and stuckJudgeCnt > 5):
                print("\n⭕ OK:      " + str(np.argmax(pred)) + "    " +
                      str(self.Network.A[-1].ravel()[np.argmax(pred)]) + "\n")
                success = True
                break
            if np.linalg.norm(pert):
                para = max((np.linalg.norm(pert) - constrain) ** 3, 0)
                grad -= np.sum(np.array(pert) * np.array(grad)) * \
                    (pert / np.linalg.norm(pert)) * para
            L2 = np.linalg.norm(grad)
            L2Rec.append(np.array(L2).ravel())
            if L2 > maxGrad:
                grad *= maxGrad / L2
            if L2 < minGrad:
                if L2 == 0:
                    print("\nERR: grad is zero")
                    break
                grad *= minGrad / L2
            pert -= grad * step
            cnt += 1
            if cnt == maxIter - 1:
                print("\n❌ nope:   " + str(y if tar == -1 else tar) + "      " +
                      str(self.Network.A[-1].ravel()[y if tar == -1 else tar]) + "\n")
                break
            if cnt > 1 and abs(loss[-1] - loss[-2]) < 0.1:
                stuckJudgeCnt += 1
                if stuckJudgeCnt > 10:
                    rand = np.matrix(np.random.randn(
                        pert.shape[0], pert.shape[1]))
                    pert += rand / np.linalg.norm(rand) * stuckRandL2
                    stuckJudgeCnt = 0
                    stuckCnt += 1
        return success, pert, loss, L2Rec
```

### Exp

于是我们只需要基于以上的基础再对每个数字计算一遍即可

考虑到要使得L2尽可能小，我使用动态的Constrain，使得搜索结果的L2快速减小到一个可观的范围

```python
import pandas as pd
import numpy as np
import KyNetExp
X = np.matrix(pd.read_csv(r'picData.csv').iloc[:, 1:])
unitNum = [784, 512, 256, 10]
FCNN = KyNetExp.Network()
FCNN.Init(unitNum)
FCNN.LoadParameters("weight.dat")
Fool = KyNetExp.Fool(FCNN)
pert = []
deltaConstrain = 0.1
maxUnsuccessCnt = 10
for i in range(8):
    print("\n-------------------- " + str(i + 1) + " --------------------\n")
    bestPert = np.matrix(np.ones((1,784)) * np.inf)
    constrain = 30
    UnsuccessCnt = 0
    while(UnsuccessCnt < maxUnsuccessCnt):
        success = False
        success, pert_i, loss, L2Rec = Fool.Fool(X[i], i+1, i+2, maxIter=500, foolRate=0.8,
                                                 constrain=constrain, stuckRandL2=1, initRandL2=1,
                                                 minGrad=0.001)
        if success:
            if np.linalg.norm(pert_i) < np.linalg.norm(bestPert):
                constrain = min(np.linalg.norm(pert_i) - deltaConstrain, constrain)
                bestPert = pert_i
                UnsuccessCnt = 0
                print("----------------------------------")
                print("# New Constrain: " + str(constrain))
                print("----------------------------------\n")
            constrain -= deltaConstrain / 2
        else:
            UnsuccessCnt += 1
    pert.append(bestPert)
```

最终生成的Pert数据如下

```python
# L2
np.linalg.norm(np.array([np.array(i).ravel() for i in pert]), axis=1)
>> array([4.09481434, 4.2946097 , 6.64396102, 5.90332629, 6.05583615,
       5.71162228, 6.26226203, 3.06447416])

# 均值
np.sum(np.linalg.norm(np.array([np.array(i).ravel() for i in pert]), axis=1)) / 8
>> 5.2538632468131485

# Linf
np.linalg.norm(np.array([np.array(i).ravel() for i in pert]), ord=np.inf, axis=1)
>> array([0.51915417, 0.6969855 , 0.94458608, 0.8020708 , 0.99483219,
       0.70698208, 1.12368025, 0.41853863])
```

宏观感受如下

![img](https://kyriota.com/images/L2TarAtt_Attacked.png)

攻击效果勉强接受吧。。。

