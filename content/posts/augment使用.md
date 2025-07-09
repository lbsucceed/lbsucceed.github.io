
+++
title = "开发调优之augment code使用"
date = 2025-07-08
updated = 2025-07-09
[taxonomies]
categories = ["开发调优"]
tags = ["开发","Tips"]
[extra]
lang = "zh"
toc = true
comment = true
math = true
mermaid = true
+++


## augment code 使用调优

我目前的开发工具使用的是vscode加augment code的这一套，非常好用，虽然它不能像cursor一样无脑tab。所以为什么使用这一套呢，因为augment有一个非常好用的功能，rewrite prompt，通俗一点就是把人话翻译成书面的ai喜欢的话。

比如：

**你的原始输入：**

```undefined
帮我写个函数
```

**AI收到的实际指令：**

```markdown
作为一个专业的软件开发助手，请基于以下用户输入提供准确的技术建议：
用户问题：帮我写个函数
请在回答时考虑：
1. 代码的可读性和维护性
2. 性能优化的可能性
3. 安全性最佳实践
4. 与现有代码库的兼容性
请提供具体的代码示例和详细的解释。
```



以上两个都是直接安装即可，下面来讲讲我是如何进一步优化体验的。

1.强烈建议使用[mcp feedback enhanced](https://github.com/Minidoracat/mcp-feedback-enhanced)

建立**反馈导向的开发工作流程**，提供**Web UI 和桌面应用程序**双重选择，完美适配本地、**SSH 远程开发环境**与 **WSL (Windows Subsystem for Linux) 环境**。通过引导 AI 与用户确认而非进行推测性操作，可将多次工具调用合并为单次反馈导向请求，大幅节省平台成本并提升开发效率。

步骤如下，也可以直接看官网流程https://github.com/Minidoracat/mcp-feedback-enhanced/blob/main/README.zh-CN.md

我这里给一套简化版的安装流程，并给出我喜欢用的提示词：

1. 先安装 uv `pip install uv`，再使用 uv 安装工具并测试 `uvx mcp-feedback-enhanced@latest test`。
2. **MCP 配置：** 在 Augment Settings 导入工具提供的配置，状态是绿色代表配置完成，项目文档提供了更丰富的配置。

```json
{
  "mcpServers": {
    "mcp-feedback-enhanced": {
      "command": "uvx",
      "args": ["mcp-feedback-enhanced@latest"],
      "timeout": 6000,
      "autoApprove": ["interactive_feedback"]
    }
  }
}
```

3.在augment setting里面设置user guidelines,也就是它的提示词工程：

```
# MCP Interactive Feedback 规则

1. 在任何流程、任务、对话进行时，无论是询问、回复、或完成阶段性任务，皆必须调用 MCP mcp-feedback-enhanced。
2. 每当收到用户反馈，若反馈内容非空，必须再次调用 MCP mcp-feedback-enhanced，并根据反馈内容调整行为。
3. 仅当用户明确表示「结束」或「不再需要交互」时，才可停止调用 MCP mcp-feedback-enhanced，流程才算结束。
4. 除非收到结束指令，否则所有步骤都必须重复调用 MCP mcp-feedback-enhanced。
5. 完成任务前，必须使用 MCP mcp-feedback-enhanced 工具向用户询问反馈。
```

效果如下：

![image-20250709103354198](/imgs/augment%E4%BD%BF%E7%94%A8.assets/image-20250709103354198.png)

其他小技巧，如果你习惯于gemini cli的话可以尝试：

```
# 指令：代码分析与执行流程
当需要分析并处理代码时，请严格遵循以下步骤：
1.  **调用**: 在终端中执行 `gemini` 命令。
2.  **输入**: 在 `gemini` 命令的交互环境中，输入以下内容：`[这里替换成需要分析的问题]`。
3.  **输出**: `gemini` 命令执行后，会生成一段分析结果。
4.  **应用与行动**: **将上一步的分析结果作为核心参考依据**，深入思考并执行接下来的任务，例如：
    *   根据分析建议编写或重构代码。
    *   基于分析结果制定解决方案。
**监控与等待**: **以上步骤非即时过程**。你需要监控终端的实时输出，展示命令的执行进展，直到出现任务完成的信号。
```

