---
name: ai-skill-sentinel
description: 专门为本地 AI Agent (如 OpenClaw) 设计的高级安全审查工具。支持递归目录扫描、上下文感知检测、Docker 沙盒隔离和本地 LLM 深度审计。
emoji: 🛡️🤖
metadata:
  openclaw:
    requires:
      bins: ["python3"]
    optional:
      bins: ["docker", "ollama"]
    version: "2.0.0"
    author: "berlin0212"
    category: "security"
    tags: ["security", "audit", "sandbox", "llm-guard", "anti-malware"]
---

# AI 技能安全哨兵 (AI-Skill Sentinel) v2.0

## 简介
AI-Skill Sentinel 是一款专为保护本地 AI 环境 (如 OpenClaw) 免受恶意 Skill 侵害的深度防御工具。
它通过 23 条检测规则、上下文感知引擎、Docker 沙盒隔离和本地 LLM 语义审计，为您建立多层安全防线。

## 核心能力
1.  **静态代码审计**: 递归扫描 Skill 目录下所有 `.md`, `.sh`, `.py`, `.js` 文件，匹配 23 条威胁特征。
2.  **上下文感知**: 智能区分 Markdown 代码示例与真实恶意指令，大幅降低误报率。
3.  **域名白名单**: 自动拦截所有非主流可信域名的外联请求。
4.  **Docker 沙盒生成**: 一键创建物理隔离的运行环境，即使 Skill 含有木马也无法溢出攻击。
5.  **LLM 深度审计**: 对接本地 Ollama API，用 70B 大模型逐行 Review 可疑代码。

## 使用场景
- 当您从 GitHub、ClawHub 或网上下载了一个未经认证的 Skill 时。
- 在安装任何包含 `.sh` 或 `.py` 脚本的自动化工具前。
- 怀疑某个已安装的 Skill 正在后台进行异常网络连接时。
- 定期审计所有已安装的 OpenClaw Skills。

## 操作指令

### 扫描 Skill
```bash
# 扫描单个文件
python3 sentinel.py /path/to/SKILL.md

# 递归扫描整个 Skill 目录 (推荐)
python3 sentinel.py /path/to/some-skill/

# 生成 Docker 沙盒 (用于中高风险 Skill)
python3 sentinel.py /path/to/skill/ --sandbox

# 启用 LLM 深度审计 (需要 Ollama 运行)
python3 sentinel.py /path/to/skill/ --llm --model qwen2:72b
```

### 批量审计所有已安装 Skills
```bash
for skill in ~/.openclaw/skills/*/; do
  echo "━━━ 正在审计: $(basename $skill) ━━━"
  python3 sentinel.py "$skill"
done
```

## 审计准则
- **0-15 分**: 🟢 安全。保持人工审批终端命令。
- **16-40 分**: 🟡 低风险。关闭 OpenClaw 的 Turbo 自动执行模式。
- **41-65 分**: 🟠 中风险。必须在 Docker 沙盒中试运行。
- **66-85 分**: 🔴 高风险。强烈建议不要安装。
- **86-100 分**: ☠️ 极危。禁止安装，立即删除并举报。

---
"安全不是一个产品，而是一个过程。始终保持怀疑，始终人工审批每一行终端命令。" 🛡️
