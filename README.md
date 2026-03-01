# AI-Skill Sentinel (AI 技能安全哨兵)

这是专门为您的 **OpenClaw** 和未来的 **128GB AI 算力中心 (FAEX1)** 打造的安全加固包。

## 📁 文件夹内容
- `SKILL.md`: 将此文件导入您的 OpenClaw，让 AI 在您的流程中主动调用本工具。
- `sentinel.py`: 核心扫描引擎。
- `rules.json`: 维护着威胁情报库，包含已知的恶意 C2 地址和恶意代码指纹。
- `_meta.json`: 技能元数据。

## 🚀 快速开始
1. **本地扫描一个 Skill**:
   ```bash
   python3 /Users/berlin/Downloads/ai-skill-sentinel/sentinel.py <文件路径>
   ```

2. **扫描您之前下的那个 Auditor (查看效果)**:
   ```bash
   python3 /Users/berlin/Downloads/ai-skill-sentinel/sentinel.py /Users/berlin/Downloads/skill-security-auditor/SKILL.md
   ```

## 🔒 物理隔离建议 (Docker)
对于风险评分超过 30 分的工作项，建议在本地创建一个极其严苛的 Docker 独立沙盒执行环境。

**创建 `Dockerfile.secure` 示例**:
```dockerfile
FROM node:20-alpine
# 移除所有不必要的二进制文件
RUN rm -rf /sbin/apk /sbin/modprobe /usr/bin/curl
# 使用非 root 用户
USER 1001
WORKDIR /app
# 挂载您的项目目录 (Read-Only)
# docker run -v ./project:/app:ro ai-sentinel
```

## ⚖️ 免责声明
本工具基于启发式分析和模式匹配，它可以拦截 90% 以上的常见恶意脚本，但无法 100% 保证对抗由顶尖骇客编写的多段混淆代码。**请始终保持人工审核终端命令的习惯。**
