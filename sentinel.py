#!/usr/bin/env python3
"""
AI-Skill Sentinel v2.1 - 本地 AI 技能安全哨兵
功能:
  1. 递归扫描整个 Skill 目录 (所有 .md, .sh, .py, .js 文件)
  2. 上下文感知检测 (区分代码示例/注释 vs 真实指令)
  3. 多级风险评分 (Critical / High / Medium / Social Engineering)
  4. 外联域名白名单审计
  5. 沙盒 Dockerfile 自动生成
  6. 本地 LLM 审计接口 (对接 Ollama API，结构化解析)
  7. JSON 报告导出 (--output)
"""

import os
import re
import json
import argparse
import subprocess
import sys
from typing import List, Dict, Tuple, Optional
from datetime import datetime

# ============================================================
#  颜色输出
# ============================================================
class Colors:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

# ============================================================
#  核心扫描引擎
# ============================================================
class SkillSentinel:
    SCAN_EXTENSIONS = {'.md', '.sh', '.py', '.js', '.ts', '.json', '.yaml', '.yml', '.toml'}

    def __init__(self, rules_path: str):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        full_path = rules_path if os.path.isabs(rules_path) else os.path.join(script_dir, rules_path)

        with open(full_path, 'r', encoding='utf-8') as f:
            self.rules = json.load(f)

        self.findings: List[Dict] = []
        self.risk_score: int = 0
        self.files_scanned: int = 0
        self.suspicious_urls: List[str] = []
        self.positive_indicators: List[str] = []

    # ----------------------------------------------------------
    #  入口：扫描文件或目录
    # ----------------------------------------------------------
    def scan(self, target_path: str):
        if os.path.isfile(target_path):
            self._scan_single_file(target_path)
        elif os.path.isdir(target_path):
            self._scan_directory(target_path)
        else:
            print(f"{Colors.RED}❌ 错误: 路径不存在 {target_path}{Colors.RESET}")
            sys.exit(1)

    # ----------------------------------------------------------
    #  递归扫描目录
    # ----------------------------------------------------------
    def _scan_directory(self, dir_path: str):
        print(f"{Colors.BLUE}📂 递归扫描目录: {dir_path}{Colors.RESET}")
        for root, dirs, files in os.walk(dir_path):
            # 跳过隐藏目录和 node_modules
            dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'node_modules']
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in self.SCAN_EXTENSIONS:
                    fpath = os.path.join(root, fname)
                    self._scan_single_file(fpath)

    # ----------------------------------------------------------
    #  扫描单个文件
    # ----------------------------------------------------------
    def _scan_single_file(self, file_path: str):
        self.files_scanned += 1
        rel_path = os.path.basename(file_path)

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            self.findings.append({
                "level": "WARN", "file": rel_path, "line": 0,
                "rule": "READ_ERR", "msg": f"无法读取文件: {e}"
            })
            return

        # 标记代码块区域 + 注释行 (用于上下文感知)
        in_code_block = False
        code_block_lines = set()
        comment_lines = set()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('```'):
                in_code_block = not in_code_block
                code_block_lines.add(i)
            elif in_code_block:
                code_block_lines.add(i)
            # 检测注释行: #, //, <!-- -->
            elif stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('<!--'):
                comment_lines.add(i)

        # 1. 规则匹配
        for category_key, level_label in [
            ('critical_patterns', '☠️ 致命'),
            ('high_patterns',     '🔴 高危'),
            ('medium_patterns',   '🟡 中危'),
            ('social_engineering','⚠️ 社工'),
        ]:
            patterns = self.rules.get(category_key, [])
            for rule in patterns:
                try:
                    matches = list(re.finditer(rule['pattern'], content, re.IGNORECASE))
                except re.error:
                    continue  # 无效正则，跳过

                for match in matches:
                    line_num = content[:match.start()].count('\n')
                    # 上下文感知：代码块或注释行内的匹配，降权为 1/3
                    is_in_example = line_num in code_block_lines
                    is_in_comment = line_num in comment_lines
                    is_context_safe = is_in_example or is_in_comment
                    actual_score = rule['score'] // 3 if is_context_safe else rule['score']
                    if is_in_example:
                        context_note = " (出现在代码示例中，已降权)"
                    elif is_in_comment:
                        context_note = " (出现在注释中，已降权)"
                    else:
                        context_note = ""

                    self.risk_score += actual_score
                    self.findings.append({
                        "level": level_label,
                        "file": rel_path,
                        "line": line_num + 1,
                        "rule": rule['id'],
                        "msg": f"{rule['name']}: {rule['desc']}{context_note}",
                        "score": actual_score
                    })

        # 2. 外联域名审计
        urls = set(re.findall(r'https?://[^\s)\]\'"`,]+', content))
        safe_domains = self.rules.get('whitelist', {}).get('safe_domains', [])
        for url in urls:
            is_safe = any(domain in url for domain in safe_domains)
            if not is_safe:
                # 同样做上下文感知
                url_pos = content.find(url)
                url_line = content[:url_pos].count('\n') if url_pos >= 0 else 0
                is_in_example = url_line in code_block_lines

                if not is_in_example:
                    self.risk_score += 15
                    self.suspicious_urls.append(url)
                    self.findings.append({
                        "level": "🌐 外联",
                        "file": rel_path,
                        "line": url_line + 1,
                        "rule": "URL",
                        "msg": f"非白名单域名: {url}",
                        "score": 15
                    })

        # 3. 正面指标
        safe_bins = self.rules.get('whitelist', {}).get('safe_bins', [])
        for safe_bin in safe_bins:
            if re.search(rf'\b{re.escape(safe_bin)}\b', content):
                if f"使用已知安全工具: {safe_bin}" not in self.positive_indicators:
                    self.positive_indicators.append(f"使用已知安全工具: {safe_bin}")

    # ----------------------------------------------------------
    #  LLM 深度审计 (对接 Ollama)
    # ----------------------------------------------------------
    def llm_audit(self, content: str, model: str = "llama3:8b",
                  ollama_url: str = "http://localhost:11434") -> Optional[str]:
        """
        调用本地 Ollama API，让大模型逐段分析可疑代码。
        需要本地已安装 Ollama 并拉取了对应模型。
        """
        prompt = f"""你是一位顶尖的网络安全专家和红队成员。
请分析以下 AI Skill 的内容，判断它是否包含以下任何一种恶意行为：
1. 试图窃取用户的 SSH 密钥、API Token 或加密货币钱包
2. 建立反弹 Shell 或与远程 C2 服务器通信
3. 通过社会工程学手段诱导用户执行危险操作
4. 使用混淆技术隐藏恶意代码（如 Base64 编码）
5. 试图提权或绕过系统安全机制

请只回答 JSON 格式：
{{"verdict": "SAFE 或 DANGEROUS", "confidence": 0-100, "reasons": ["原因1", "原因2"]}}

--- 待分析内容 ---
{content[:4000]}
--- 内容结束 ---"""

        try:
            import urllib.request
            data = json.dumps({
                "model": model,
                "prompt": prompt,
                "stream": False
            }).encode('utf-8')

            req = urllib.request.Request(
                f"{ollama_url}/api/generate",
                data=data,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read().decode('utf-8'))
                raw_response = result.get('response', '')

                # 尝试从 LLM 回复中提取结构化 JSON
                try:
                    # 支持 LLM 回复中包裹在 ```json ... ``` 里的情况
                    json_match = re.search(r'\{[^{}]*"verdict"[^{}]*\}', raw_response, re.DOTALL)
                    if json_match:
                        parsed = json.loads(json_match.group())
                        return {
                            "verdict": parsed.get("verdict", "UNKNOWN"),
                            "confidence": parsed.get("confidence", 0),
                            "reasons": parsed.get("reasons", []),
                            "raw": raw_response
                        }
                except (json.JSONDecodeError, AttributeError):
                    pass

                # 解析失败则降级为原始文本
                return {"verdict": "UNKNOWN", "confidence": 0, "reasons": [], "raw": raw_response}
        except Exception as e:
            return {"verdict": "ERROR", "confidence": 0, "reasons": [str(e)], "raw": ""}

    # ----------------------------------------------------------
    #  生成 Docker 沙盒配置
    # ----------------------------------------------------------
    def generate_sandbox(self, output_dir: str):
        """为高风险 Skill 生成 Docker 隔离运行环境"""
        dockerfile_content = """# AI-Skill Sentinel 生成的安全沙盒
# 用途: 在隔离环境中测试可疑的 AI Skill
FROM node:20-alpine

# 1. 移除危险二进制
RUN rm -f /usr/bin/wget /sbin/apk 2>/dev/null || true

# 2. 创建非特权用户
RUN adduser -D -s /bin/sh sandboxuser
USER sandboxuser
WORKDIR /home/sandboxuser/skill

# 3. 限制能力 (需在 docker run 时配合 --cap-drop=ALL)
# 运行命令:
#   docker build -t skill-sandbox -f Dockerfile.sandbox .
#   docker run --rm -it \\
#     --cap-drop=ALL \\
#     --network=none \\
#     --read-only \\
#     --tmpfs /tmp:rw,noexec,nosuid \\
#     -v $(pwd)/skill-to-test:/home/sandboxuser/skill:ro \\
#     skill-sandbox sh

CMD ["sh"]
"""
        dockerfile_path = os.path.join(output_dir, "Dockerfile.sandbox")
        with open(dockerfile_path, 'w') as f:
            f.write(dockerfile_content)

        compose_content = """# AI-Skill Sentinel 安全沙盒 Docker Compose
version: "3.8"
services:
  sandbox:
    build:
      context: .
      dockerfile: Dockerfile.sandbox
    cap_drop:
      - ALL
    network_mode: "none"
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid
    volumes:
      - ./skill-to-test:/home/sandboxuser/skill:ro
    stdin_open: true
    tty: true
"""
        compose_path = os.path.join(output_dir, "docker-compose.sandbox.yml")
        with open(compose_path, 'w') as f:
            f.write(compose_content)

        print(f"{Colors.GREEN}🐳 沙盒配置已生成:{Colors.RESET}")
        print(f"   - {dockerfile_path}")
        print(f"   - {compose_path}")
        print(f"   使用方法: docker compose -f docker-compose.sandbox.yml run sandbox")

    # ----------------------------------------------------------
    #  打印审计报告
    # ----------------------------------------------------------
    def print_report(self, use_llm: bool = False, skill_content: str = ""):
        score = min(self.risk_score, 100)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 分级星标
        if score <= 15:
            verdict = f"{Colors.GREEN}🟢 安全 — 未检测到恶意特征{Colors.RESET}"
            action  = "可以安装。建议保持人工审批终端命令的习惯。"
        elif score <= 40:
            verdict = f"{Colors.YELLOW}🟡 低风险 — 存在少量可疑特征{Colors.RESET}"
            action  = "谨慎安装。关闭 OpenClaw 的 Turbo 自动执行模式。"
        elif score <= 65:
            verdict = f"{Colors.YELLOW}🟠 中风险 — 多项可疑行为{Colors.RESET}"
            action  = "建议在 Docker 沙盒中试运行。使用 --sandbox 参数生成隔离配置。"
        elif score <= 85:
            verdict = f"{Colors.RED}🔴 高风险 — 检测到严重恶意指标{Colors.RESET}"
            action  = "强烈建议不要安装！如有必要，仅在隔离容器中分析。"
        else:
            verdict = f"{Colors.RED}{Colors.BOLD}☠️  极危 — 确认包含恶意代码特征{Colors.RESET}"
            action  = "禁止安装！立即删除该 Skill 并向社区举报。"

        print()
        print(f"{Colors.BOLD}{'═' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}    🛡️  AI-SKILL SENTINEL v2.0 — 安全审计报告{Colors.RESET}")
        print(f"{'═' * 60}")
        print(f"  审计时间: {now}")
        print(f"  扫描文件: {self.files_scanned} 个")
        print(f"{'─' * 60}")
        print(f"  {Colors.BOLD}风险评分: {score}/100{Colors.RESET}")
        print(f"  {Colors.BOLD}最终裁定: {verdict}{Colors.RESET}")
        print(f"{'─' * 60}")

        # 按严重性分组打印
        if self.findings:
            # 去重 (同一规则在同一文件只报一次)
            seen = set()
            unique_findings = []
            for f in self.findings:
                key = (f['rule'], f['file'])
                if key not in seen:
                    seen.add(key)
                    unique_findings.append(f)

            # 排序 (严重的在前)
            level_order = {'☠️ 致命': 0, '🔴 高危': 1, '🟡 中危': 2, '🌐 外联': 3, '⚠️ 社工': 4, 'WARN': 5}
            unique_findings.sort(key=lambda x: level_order.get(x['level'], 99))

            print(f"\n  {Colors.BOLD}详细发现 ({len(unique_findings)} 项):{Colors.RESET}")
            for f in unique_findings:
                color = Colors.RED if '致命' in f['level'] or '高危' in f['level'] else Colors.YELLOW
                print(f"  {color}  [{f['level']}] {f['file']}:{f['line']} — [{f['rule']}] {f['msg']}{Colors.RESET}")
        else:
            print(f"\n  {Colors.GREEN}✨ 恭喜！未检测到任何已知的恶意模式。{Colors.RESET}")

        # 可疑外联
        if self.suspicious_urls:
            print(f"\n  {Colors.YELLOW}🌐 可疑外联地址 ({len(self.suspicious_urls)} 个):{Colors.RESET}")
            for url in set(self.suspicious_urls):
                print(f"  {Colors.YELLOW}    → {url}{Colors.RESET}")

        # 正面指标
        if self.positive_indicators:
            print(f"\n  {Colors.GREEN}✅ 正面指标:{Colors.RESET}")
            for p in self.positive_indicators[:5]:
                print(f"  {Colors.GREEN}    ✓ {p}{Colors.RESET}")

        # LLM 审计
        if use_llm and skill_content:
            print(f"\n  {Colors.BLUE}🤖 正在调用本地 LLM 进行深度语义审计...{Colors.RESET}")
            llm_result = self.llm_audit(skill_content)
            if isinstance(llm_result, dict):
                v = llm_result.get('verdict', 'UNKNOWN')
                c = llm_result.get('confidence', 0)
                v_color = Colors.GREEN if v == 'SAFE' else Colors.RED
                print(f"  {v_color}  LLM 裁定: {v} (置信度: {c}%){Colors.RESET}")
                for reason in llm_result.get('reasons', []):
                    print(f"  {Colors.BLUE}    • {reason}{Colors.RESET}")
            else:
                print(f"  {Colors.BLUE}  LLM 分析结果: {llm_result}{Colors.RESET}")
            self._llm_result = llm_result

        print(f"\n{'─' * 60}")
        print(f"  {Colors.BOLD}📋 建议操作: {action}{Colors.RESET}")
        print(f"{'═' * 60}\n")


# ============================================================
#  命令行入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="🛡️ AI-Skill Sentinel v2.0 — 本地 AI 技能安全审计工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  扫描单个文件:      python3 sentinel.py ./SKILL.md
  扫描整个 Skill 目录: python3 sentinel.py ./some-skill/
  生成沙盒配置:      python3 sentinel.py ./some-skill/ --sandbox
  启用 LLM 深度审计:  python3 sentinel.py ./SKILL.md --llm
  指定 Ollama 模型:   python3 sentinel.py ./SKILL.md --llm --model qwen2:72b
        """
    )
    parser.add_argument("target", help="待扫描的文件路径或 Skill 目录")
    parser.add_argument("--rules", default="rules.json", help="规则库路径 (默认: rules.json)")
    parser.add_argument("--sandbox", action="store_true", help="为高风险 Skill 生成 Docker 沙盒配置")
    parser.add_argument("--llm", action="store_true", help="启用本地 LLM 深度语义审计 (需要 Ollama)")
    parser.add_argument("--model", default="llama3:8b", help="LLM 模型名称 (默认: llama3:8b)")
    parser.add_argument("--output", metavar="FILE", help="将审计报告导出为 JSON 文件")
    args = parser.parse_args()

    print(f"\n{Colors.BOLD}🛡️  AI-Skill Sentinel v2.1 启动{Colors.RESET}")
    print(f"{Colors.DIM}   \"安全不是产品，是过程。\"{Colors.RESET}\n")

    # 初始化引擎
    sentinel = SkillSentinel(args.rules)

    # 执行扫描
    sentinel.scan(args.target)

    # 读取主文件内容 (用于 LLM)
    skill_content = ""
    if args.llm:
        target = args.target
        if os.path.isdir(target):
            skill_md = os.path.join(target, "SKILL.md")
            if os.path.exists(skill_md):
                target = skill_md
        if os.path.isfile(target):
            with open(target, 'r', encoding='utf-8', errors='ignore') as f:
                skill_content = f.read()

    # 输出报告
    sentinel.print_report(use_llm=args.llm, skill_content=skill_content)

    # JSON 报告导出
    score = min(sentinel.risk_score, 100)
    if args.output:
        report_data = {
            "version": "2.1",
            "timestamp": datetime.now().isoformat(),
            "target": os.path.abspath(args.target),
            "files_scanned": sentinel.files_scanned,
            "risk_score": score,
            "verdict": (
                "SAFE" if score <= 15 else
                "LOW_RISK" if score <= 40 else
                "MEDIUM_RISK" if score <= 65 else
                "HIGH_RISK" if score <= 85 else
                "CRITICAL"
            ),
            "findings": sentinel.findings,
            "suspicious_urls": list(set(sentinel.suspicious_urls)),
            "positive_indicators": sentinel.positive_indicators,
            "llm_audit": getattr(sentinel, '_llm_result', None)
        }
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        print(f"{Colors.GREEN}📄 JSON 报告已导出: {args.output}{Colors.RESET}")

    # 沙盒生成
    if args.sandbox:
        output_dir = args.target if os.path.isdir(args.target) else os.path.dirname(args.target)
        sentinel.generate_sandbox(output_dir)

    # 返回退出码 (方便 CI/CD 集成)
    sys.exit(1 if score >= 65 else 0)


if __name__ == "__main__":
    main()
