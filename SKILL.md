---
name: ai-skill-sentinel
description: 专门为本地 AI Agent (如 OpenClaw) 设计的高级安全审查工具，支持行为模式匹配与沙盒化隔离逻辑建议。
emoji: 🛡️🤖
metadata:
  openclaw:
    requires:
      bins: ["python3", "docker"]
    version: "1.0.0"
---

# AI 技能安全哨兵 (AI-Skill Sentinel)

## 简介
AI-Skill Sentinel 是一款专为保护本地 AI 环境免受恶意 Skill 侵害的防御工具。由于第三方生成的 Skill 往往包含不受控的终端指令，该工具通过深度扫描、行为特征检测和未来的 LLM 自审计，为您建立第一道安全防线。

## 核心能力
1. **静态代码审计 (Static Audit)**: 扫描 `SKILL.md` 和配套脚本，识别已知的恶意软件特征和恶意 C2 (命令控制) 服务器 IP。
2. **提权与外联检测**: 自动检测 `sudo` 提权、反弹 Shell (`nc`)、以及对本地敏感路径 (`~/.ssh`, `KeyChain`) 的非经授权访问。
3. **域名白名单校验**: 拦截所有非主流、不知名的可信域名外联请求。
4. **沙盒化运行建议**: 提供并在终端生成基于 Docker 的物理隔离启动模板，确保即使 Skill 包含木马也无法溢出攻击您的 Mac 或工作站。

## 使用场景
- 当您从 GitHub 或网上下载了一个未经认证的 Skill 时。
- 在安装任何包含 `analyze-skill.sh` 等脚本的自动化工具前。
- 怀疑某个已安装的 Skill 正在后台进行异常网络连接时。

## 操作指令集

### 1. 扫描新下载的 Skill
在终端运行：
```bash
python3 /Users/berlin/Downloads/ai-skill-sentinel/sentinel.py <待审查文件路径>
```

### 2. 生成沙盒隔离配置文件
命令 Agent 为指定项目生成 `Dockerfile.secure` 以进行隔离。

## 审计准则
- **0-30 分**: 安全级别高，但仍需对 `curl` 命令保持警惕。
- **31-60 分**: 中等风险。必须在 Docker 沙盒中尝试运行，且禁止开启 OpenClaw 的 `Turbo` 自动审批功能。
- **61-100 分**: 极高风险。判定为后门、木马或恶意挖矿脚本，严禁安装。

---
"安全不是一个产品，而是一个过程。始终保持怀疑，始终人工审批每一行终端命令。" 🦞🛡️
