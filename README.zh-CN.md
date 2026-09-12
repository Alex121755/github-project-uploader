# GitHub Project Uploader

一个安全优先的 Codex 插件：选择本地项目，执行失败关闭式预检，并且只有在用户明确确认后，才把一个确定的 Git 提交推送到 GitHub。

[English README](README.md) · [安全模型](docs/security-model.md) · [安全漏洞报告](SECURITY.md)

> [!IMPORTANT]
> 这是一个独立开源项目，并非 GitHub 或 OpenAI 官方产品，也不代表这两家公司对项目进行了背书。

## 核心功能

- 在支持的 Codex 本地插件界面里点选已注册项目。
- 通过绝对路径添加新的项目根目录。
- 每次上传前生成十分钟有效、仅能使用一次的预检计划。
- 在当前文件和有界 Git 历史中启发式检查常见凭据。
- 检查 Git 工作区、索引、隐藏标志、远程地址、文件大小及危险配置。
- 通过临时隔离的 Git 传输仓库推送一个确定的 commit，并核对远程分支 OID。
- 默认创建私有仓库；公开仓库必须额外确认完整的 `账号/仓库名`。

## 支持范围

- macOS 或 Linux；暂不支持 Windows。
- Python 3.10+，命令名为 `python3`。
- Git、[GitHub CLI](https://cli.github.com/) 和 `/usr/bin/ssh`。
- 支持本地插件与 MCP Apps 的 Codex 界面。

MCP 服务端只使用 Python 标准库，不需要安装 pip 依赖。

当前版本不支持 Git LFS、子模块、嵌套仓库、裸仓库、浅克隆或部分克隆，也不是同步或备份工具。

## 从 GitHub 安装

添加这个仓库市场并安装插件：

```bash
codex plugin marketplace add Alex121755/github-project-uploader --ref main
codex plugin add github-project-uploader@alex121755-tools
```

只卸载插件并保留仓库市场：

```bash
codex plugin remove github-project-uploader@alex121755-tools
```

安装后新建一个 Codex 任务，让新的技能和 MCP 工具被加载。

以后更新：

```bash
codex plugin marketplace upgrade alex121755-tools
codex plugin add github-project-uploader@alex121755-tools
```

## 连接 GitHub

插件用 GitHub CLI 查询账号和创建仓库，用 SSH 推送 Git 内容：

```bash
gh auth login --git-protocol ssh
gh auth status
/usr/bin/ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=15 -T git@github.com
```

GitHub SSH 验证成功时会打印认证成功信息，但通常仍返回非零状态，因为 GitHub 不提供 shell。上传过程会忽略用户 SSH 配置，并固定连接 `github.com:22`；依赖自定义代理或 `ProxyJump` 的环境暂不支持。

仓库只会创建到当前已认证的个人 GitHub 账号下；当前版本不能选择组织作为 owner。

## 使用方法

在新的 Codex 任务里输入：

```text
选择一个项目上传到 GitHub
```

然后：

1. 点选一个项目，或添加一个准确的项目根目录。
2. 输入仓库名并运行预检。
3. 处理所有阻止项，并认真查看警告。
4. 私有仓库可以在卡片内确认。
5. 公开仓库必须回到对话中，明确确认预检显示的完整 `owner/repository`。

计划十分钟后过期且只能执行一次；项目发生实质变化后必须重新预检。

## 会发生哪些改动

| 项目状态 | 本地改动 | GitHub 改动 |
| --- | --- | --- |
| 普通文件夹 | 初始化 `main`、按 `.gitignore` 暂存文件、创建 `Initial project upload` 根提交、添加 `origin` | 创建仓库并推送该提交 |
| 已初始化但还没有 commit 的 Git 仓库 | 按 `.gitignore` 暂存文件、创建 `Initial project upload` 根提交，并在没有 `origin` 时添加它 | 目标不存在时创建；已有匹配 `origin` 时核对可见性；然后推送该提交 |
| 已有至少一个 commit、状态干净且没有 `origin` 的 Git 仓库 | 添加准确的 GitHub SSH `origin`，不新建提交 | 要求目标仓库尚不存在，然后创建并把当前 `HEAD` 推送到当前分支 |
| 已有且干净、`origin` 与目标完全匹配的 Git 仓库 | 不改写历史，不新建提交 | 目标不存在时创建；已存在时核对可见性；然后把当前 `HEAD` 推送到当前分支 |
| 中途失败 | 之前创建的 `.git`、提交或 `origin` 可能保留 | GitHub 上可能已留下空仓库 |

插件只在远程分支 OID 与本地目标提交完全一致后报告成功。它不会自动回滚或删除任何内容；修复网络/认证问题后重新预检即可。删除远程仓库或撤销本地 Git 初始化必须由用户另行明确执行。

如果本地 `origin` 尚未与准确目标匹配，插件绝不会接管 GitHub 上已经存在的仓库。

## 安全边界

预检会检查常见凭据、敏感文件名、脏工作区、索引/工作树不一致、隐藏索引状态、危险 Git 配置、远程冲突、体积限制和不支持的仓库结构。它不会证明项目不存在密钥、个人信息、恶意代码、依赖漏洞、许可证冲突或组织策略问题。

主要上限包括：50,000 个文件、2 GiB 选定内容、单文件 50 MiB 警告/100 MiB 阻止、历史对象与历史路径各 200,000。扫描达到预算上限时会阻止上传，而不是静默跳过。完整说明见[安全模型](docs/security-model.md)。

## 数据与隐私

文件和 Git 历史在本机扫描；列表和预检会向 GitHub 查询当前账号及目标仓库元数据；只有确认执行时才推送项目内容。Codex 会收到项目路径及脱敏后的发现信息。

私有状态保存在：

```text
$CODEX_HOME/github-project-uploader/
```

状态文件可能包含项目路径、目标仓库、commit/branch 元数据及最后成功的 URL，不保存项目文件内容，也不会复制 GitHub token。Token 的保存由 GitHub CLI 和操作系统负责。

## 开发与测试

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -W error::ResourceWarning -m unittest discover -s tests -v
python3 -m py_compile scripts/server.py scripts/uploader_core.py
python3 -m json.tool .codex-plugin/plugin.json >/dev/null
python3 -m json.tool .mcp.json >/dev/null
python3 -m json.tool .agents/plugins/marketplace.json >/dev/null
```

详细贡献规则见 [CONTRIBUTING.md](CONTRIBUTING.md)。项目采用 [MIT License](LICENSE)。
