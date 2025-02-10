+++
title = "uv再体验"
date = 2025-01-25
updated = 2025-02-10
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

另外我终于明白了跟着官方教程准没错，而不是跟着民间大师的过时教程，那个总归只是参考而已。

添加一个查看内存空间的linux小命令

```bash
(xpu-test) root@DESKTOP-SN2FD5H:~/xpu_test# du -h --max-depth=1
120K    ./.git
74M     ./.venv
75M     .
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



