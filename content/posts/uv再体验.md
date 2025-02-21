+++
title = "uv再体验"
date = 2025-01-27
updated = 2025-02-21
[taxonomies]
categories = ["Python Tips"]
tags = ["conda", "python","uv"]
[extra]
lang = "zh"
toc = true
comment = true
math = true
mermaid = true
+++

## UV usage

I have wrote an article on Jan.18.2025 .In that article I thought uv is not a useful tool as I thought. However, here in this time I will say "Nothing is better than UV".

## UV is all you need

### Install & Uninstall

In windows, we can download and install uv with a standalone installer.

```shell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

<div style="padding: 15px; border: 1px solid transparent; border-color: transparent; margin-bottom: 20px; border-radius: 4px; color: #8a6d3b;; background-color: #fcf8e3; border-color: #faebcc;">
&#x1F628<b> Watchout：When you try to instal in this method, adding uv bin in you environment path such as:`C:\Users\HP\.local\bin` in windows</b>
</div>

Then you can use it anywhere.

When uv is installed via the standalone installer, it can update itself on-demand:

```shell
uv self update
```

You can use

```shell
$ uv pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
```

install stable, CPU-only PyTorch on Windows.

> 上面的方式并不可行。
>
> 建议还是使用官方建议的操作进行食用。

[参考issue](https://github.com/astral-sh/uv/issues/8344#issuecomment-2426120753)

### ModuleNotFoundError: No module named 'pkg_resources'

这个问题并不会出现在conda中，但却在uv使用的时候出现了，并且在经历了一个劲的钻牛角尖后我终于知道并不是安装包的问题了，而是缺少一个依赖，setuptools,我猜测可能是我将makeupsafe降级了之后这个安装包受损导致的。

```shell
(xpu-test) root@DESKTOP-SN2FD5H:~/xpu_test# python -c "import torch; import intel_extension_for_pytorch as ipex; print(torch.__version__); print(ipex.__version__);"
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "/root/xpu_test/.venv/lib/python3.11/site-packages/intel_extension_for_pytorch/__init__.py", line 120, in <module>
    from . import llm
  File "/root/xpu_test/.venv/lib/python3.11/site-packages/intel_extension_for_pytorch/llm/__init__.py", line 2, in <module>
    from .frontend import optimize
  File "/root/xpu_test/.venv/lib/python3.11/site-packages/intel_extension_for_pytorch/llm/frontend.py", line 1, in <module>
    from intel_extension_for_pytorch.transformers.optimize import optimize
  File "/root/xpu_test/.venv/lib/python3.11/site-packages/intel_extension_for_pytorch/transformers/__init__.py", line 1, in <module>
    from .optimize import optimize_transformers
  File "/root/xpu_test/.venv/lib/python3.11/site-packages/intel_extension_for_pytorch/transformers/optimize.py", line 4, in <module>
    import pkg_resources
ModuleNotFoundError: No module named 'pkg_resources'
(xpu-test) root@DESKTOP-SN2FD5H:~/xpu_test# uv add pkg_resources
  × No solution found when resolving dependencies for split ((python_full_version >= '3.12' and platform_machine != 'aarch64' and sys_platform == 'linux') or
  │ (python_full_version >= '3.12' and sys_platform != 'darwin' and sys_platform != 'linux')):
  ╰─▶ Because there are no versions of pkg-resources and your project depends on pkg-resources, we can conclude that your project's requirements are unsatisfiable.
  help: If you want to add the package regardless of the failed resolution, provide the `--frozen` flag to skip locking and syncing.
(xpu-test) root@DESKTOP-SN2FD5H:~/xpu_test# uv pip install pkg_resources
  × No solution found when resolving dependencies:
  ╰─▶ Because there are no versions of pkg-resources and you require pkg-resources, we can conclude that your requirements are unsatisfiable.
(xpu-test) root@DESKTOP-SN2FD5H:~/xpu_test# uv add setuptools
Resolved 21 packages in 6.23s
Prepared 1 package in 9.65s
Installed 1 package in 48ms
 + setuptools==70.2.0
(xpu-test) root@DESKTOP-SN2FD5H:~/xpu_test# python -c "import torch; import intel_extension_for_pytorch as ipex; print(torch.__version__); print(ipex.__version__);"
2.5.0+cpu
2.5.0+cpu
```



还有一个简单的测试安装是否成功的脚本

```bash
(xpu-test) root@DESKTOP-SN2FD5H:~/xpu_test# python -c "import torch; import intel_extension_for_pytorch as ipex; print(torch.__version__); print(ipex.__version__);"
2.5.0+cpu
2.5.0+cpu
```

下面是我以后的安装模板，其中pytorch的安装源可能要换成cuda版本。

```toml
[project]
name = "xpu-test"
version = "0.1.0"
description = "Add your description here"
readme = "README.md"
requires-python = ">=3.11"
dependencies = [
    "intel-extension-for-pytorch==2.5.0",
    "markupsafe==2.1.3",
    "medpy>=0.5.2",
    "oneccl-bind-pt==2.5.0",
    "opencv-python>=4.11.0.86",
    "setuptools>=70.2.0",
    "tensorboard>=2.18.0",
    "torch==2.5.0",
    "torchaudio==2.5.0",
    "torchvision==0.20.0",
    "yacs>=0.1.8",
]
# 换源以及加上软链接，这个是非常必要的，防止占用空间。。。
[tool.uv]
link-mode = "symlink"
index-url = "https://pypi.tuna.tsinghua.edu.cn/simple"
# UV官方文档所建议的安装程序。
[tool.uv.sources]
intel-extension-for-pytorch={index = 'torch-intel'}
oneccl_bind_pt={index = 'torch-intel'}
torch = [
  { index = "pytorch-cpu" },
]
torchvision = [
  { index = "pytorch-cpu" },
]

[[tool.uv.index]]
name = "torch-intel"
url = "https://pytorch-extension.intel.com/release-whl/stable/cpu/us"
explicit = true


[[tool.uv.index]]
name = "pytorch-cpu"
url = "https://download.pytorch.org/whl/cpu"
explicit = true


# [[index]]
# url = "https://test.pypi.org/simple"
# default = true

# [tool.uv.pip]


```



### 关于一个报错

```bash
PS D:\3rdWinterVacation\acadamic\DG\DofeandCDDSA> uv add medpy opencv-python segmentation-models-pytorch tensorboard torch torchvision yacs matplotlib 
Resolved 64 packages in 1.85s                                                                                                                                         
error: Distribution `torch==2.6.0 @ registry+https://download.pytorch.org/whl/cpu` can't be installed because it doesn't have a source distribution or wheel for the current platform

hint: You're on Windows (`win_amd64`), but `torch` (v2.6.0) only has wheels for the following platform: `macosx_11_0_arm64`
```

这个错误在[uv/issues/10843](https://github.com/astral-sh/uv/issues/10843#issuecomment-2607649056) 得到解决，删除lock文件即可，但不知道这个是否为最优做法。

### 关于之前的一个报错，就是无法从镜像源里面下载torch

参考：[如何使用pip从镜像源里面下载torch+cuda](https://blog.csdn.net/YY007H/article/details/141962724)

```toml
[tool.uv.sources]
intel-extension-for-pytorch={index = 'torch-intel'}
oneccl_bind_pt={index = 'torch-intel'}
torch = [
  { index = "pytorch-cpu" },
]
torchvision = [
  { index = "pytorch-cpu" },
]

[[tool.uv.index]]
name = "torch-intel"
url = "https://pytorch-extension.intel.com/release-whl/stable/cpu/us"
explicit = true


[[tool.uv.index]]
name = "pytorch-cpu"
url = "https://download.pytorch.org/whl/cpu"
explicit = true
```

如果单纯使用这套模板会报错，并不会正确在阿里云里面下载torch，如果改掉了url的话，而应该在tool.uv里面添加一个find-links参数，这样就能有效的解决问题。

```toml
[tool.uv]
link-mode = "symlink"
index-url = "https://pypi.tuna.tsinghua.edu.cn/simple"
find-links = "https://mirrors.aliyun.com/pytorch-wheels/cu118"
```

参考：

[查找对应的torch版本](https://pytorch.org/get-started/previous-versions/)

[uv.toml配置文件](https://docs.astral.sh/uv/reference/settings/#pip_find-links)



### Can't use tkinter with new venv set up with uv 

参考：

[这个issue的解决方法比较有效](https://github.com/astral-sh/uv/issues/7036#issuecomment-2421594826)

```python 
from os import environ
from pathlib import Path
from sys import base_prefix

environ["TCL_LIBRARY"] = str(Path(base_prefix) / "lib" / "tcl8.6")
environ["TK_LIBRARY"] = str(Path(base_prefix) / "lib" / "tk8.6")

print(environ["TCL_LIBRARY"])
print(environ["TK_LIBRARY"])

from tkinter import *
from tkinter import ttk
root = Tk()
frm = ttk.Frame(root, padding=10)
frm.grid()
ttk.Label(frm, text="Hello World!").grid(column=0, row=0)
ttk.Button(frm, text="Quit", command=root.destroy).grid(column=1, row=0)
root.mainloop()
```

在所需要的代码里面加上这段即可。