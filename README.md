# AI-Skill Sentinel v2.0 🛡️🤖

**专为本地 AI Agent (如 OpenClaw) 设计的高级安全审查工具。**

对比同类工具 (如 `akhmittra/skill-security-auditor`):
- ✅ **23 条检测规则** (vs 对方 20 条)，覆盖 MITRE ATT&CK 威胁框架
- ✅ **上下文感知**: 区分代码示例 vs 真实恶意指令，大幅降低误报率
- ✅ **递归目录扫描**: 自动遍历 `.md`, `.sh`, `.py`, `.js` 等所有风险文件  
- ✅ **Docker 沙盒生成**: 一键为可疑 Skill 创建物理隔离运行环境
- ✅ **本地 LLM 审计**: 对接 Ollama API，用 70B 大模型逐行 Review 代码
- ✅ **零外部依赖**: 纯 Python 标准库，自身不引入任何供应链风险

## 📁 文件结构
```
ai-skill-sentinel/
├── sentinel.py          # 核心扫描引擎 (v2.0)
├── rules.json           # 威胁情报数据库 (23 条规则)
├── SKILL.md             # OpenClaw 技能定义文件
├── _meta.json           # 技能元数据
└── README.md            # 本文档
```

## 🚀 快速开始

### 1. 扫描单个 SKILL.md 文件
```bash
python3 sentinel.py /path/to/some-skill/SKILL.md
```

### 2. 递归扫描整个 Skill 目录 (推荐)
```bash
python3 sentinel.py /path/to/some-skill/
```

### 3. 为可疑 Skill 生成 Docker 沙盒
```bash
python3 sentinel.py /path/to/suspicious-skill/ --sandbox
```
这会在目标目录下生成:
- `Dockerfile.sandbox` — 极简化的隔离容器
- `docker-compose.sandbox.yml` — 一键启动的沙盒配置

启动沙盒:
```bash
docker compose -f docker-compose.sandbox.yml run sandbox
```

### 4. 启用本地 LLM 深度审计 (需要 Ollama)
```bash
# 先确保 Ollama 已运行并下载了模型
ollama pull llama3:8b

# 然后运行带 LLM 的审计
python3 sentinel.py /path/to/skill/ --llm

# 指定更强的模型 (适用于 128GB 内存的机器)
python3 sentinel.py /path/to/skill/ --llm --model qwen2:72b
```

## 📊 风险评分系统

| 分数 | 等级 | 图标 | 建议操作 |
|:-----|:-----|:-----|:---------|
| 0-15 | 安全 | 🟢 | 可以安装，保持人工审批 |
| 16-40 | 低风险 | 🟡 | 谨慎安装，关闭 Turbo 模式 |
| 41-65 | 中风险 | 🟠 | 仅在 Docker 沙盒中运行 |
| 66-85 | 高风险 | 🔴 | 强烈建议不要安装 |
| 86-100 | 极危 | ☠️ | 禁止安装，立即删除并举报 |

## 🔍 检测能力覆盖

### 致命级 (8 条)
```
C01: 提权尝试 (sudo, chmod +s, setuid)
C02: 反弹 Shell (nc, /dev/tcp, mkfifo)
C03: 敏感路径扫描 (SSH 密钥, 浏览器密码, KeyChain)
C04: 静默远程执行 (curl | bash)
C05: Base64 隐藏载荷
C06: 动态代码执行 (eval, exec, new Function)
C07: 已知恶意 C2 服务器 IP (ClawHavoc 攻击特征)
C08: ClawHavoc 假安装包
```

### 高危级 (7 条)
```
H01-H07: 可疑二进制下载、SSH 密钥操作、加密货币钱包、
         环境变量窃取、定时任务注入、DNS 隧道、进程注入
```

### 中危级 (5 条)
```
M01-M05: 文件写操作、网络监听端口、子进程生成、文件权限修改、打包操作
```

### 社工级 (3 条)
```
S01-S03: 紧迫催促语言、虚假权威声明、恐吓战术
```

## 🧠 上下文感知引擎

**这是本工具对比同类最大的技术优势。**

传统扫描器看到 `curl | bash` 就报警，但如果这段文字出现在 Markdown 的代码块 (`` ``` ``) 中作为文档示例，就不应该被判定为高危。

Sentinel v2.0 会：
1. 预先标记 Markdown 文件中所有代码块的行号范围
2. 当检测到匹配时，判断该匹配是否在代码块内
3. 如果在代码块内，将该规则的**风险分自动降至 1/3**

这大幅降低了误报率 (False Positive)，让您不会因为文档里写了一个教程示例就被吓得不敢安装。

## ⚖️ 免责声明
本工具基于启发式分析和模式匹配。它可以拦截绝大多数常见恶意脚本，但无法 100% 防御顶尖骇客编写的高度混淆代码。**请始终保持人工审核终端命令的习惯。始终保持怀疑。**

## 📄 许可证
MIT License
