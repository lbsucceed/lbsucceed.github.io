
+++
title = "如何从powershell激活不同的anaconda环境"
date = 2025-01-18
updated = 2025-01-22
[taxonomies]
categories = ["DeepLearning"]
tags = ["conda", "python","错误合集"]
[extra]
lang = "zh"
toc = true
comment = true
math = true
mermaid = true
+++

<!-- ## 如何从powershell激活不同的anaconda环境 -->

​	因为自己一直用的是linux环境，最近终于删掉了双系统，改用wsl2了，不过我还是想体验一下windows下的python环境管理。一开始选择了uv，但这个时髦小玩意并没有一个号的换源方案，最后还是换成我熟悉的miniconda了。

​	但实际操作时却遇到了一个问题，比如当添加了script和bin的全局环境变量后，我依旧不能直接在powershell中直接激活我的conda环境。根据网上和官方文档所得知，需要`在管理员下取消powershell的脚本`执行策略，比如一开始脚本执行策略是restricted。在初次管理员下运行的时候会报错。

```powershell
Windows PowerShell
版权所有（C） Microsoft Corporation。保留所有权利。

安装最新的 PowerShell，了解新功能和改进！https://aka.ms/PSWindows

. : 无法加载文件 C:\Users\87897\Documents\WindowsPowerShell\profile.ps1，因为在此系统上禁止运行脚本。有关详细信息，请参
阅 https:/go.microsoft.com/fwlink/?LinkID=135170 中的 about_Execution_Policies。
所在位置 行:1 字符: 3
+ . 'C:\Users\87897\Documents\WindowsPowerShell\profile.ps1'
+   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : SecurityError: (:) []，PSSecurityException

```

输入 `get-ExecutionPolicy` 输出 `Restricted`，即脚本执行策略受限。

```powershell
PS C:\Windows\system32> get-ExecutionPolicy
Restricted
```

这里我们直接进行调整

```powershell
PS C:\Windows\system32> set-ExecutionPolicy RemoteSigned
```

然后再次查看策略

```powershell
PS C:\Users\HP> get-ExecutionPolicy
RemoteSigned
```

接下来我们运行`conda init powershell` ,然后退出，再次开启powershell，即可发现已经可以激活环境了。

```powershell
(base) PS C:\Users\HP> conda activate dl
(dl) PS C:\Users\HP>
```

参考：

1. [stackOverflow](https://stackoverflow.com/questions/47800794/how-to-activate-different-anaconda-environment-from-powershell?rq=1)
2. [cnblogs](https://www.cnblogs.com/dereen/p/ps_conda_env.html)
3. [powershell问题](https://blog.csdn.net/qq_42951560/article/details/123859735)

<!-- [^1]: First footnote. -->