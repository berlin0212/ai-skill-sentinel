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
import hashlib
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

    # 自排除：扫描时跳过 Sentinel 自身的文件，防止误报
    SELF_EXCLUDE_FILES = {
        'sentinel.py', 'update_rules.py', 'rules.json',
        'ioc_blacklist.json', 'README.md', 'SKILL.md', '_meta.json'
    }

    def __init__(self, rules_path: str):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        full_path = rules_path if os.path.isabs(rules_path) else os.path.join(script_dir, rules_path)

        with open(full_path, 'r', encoding='utf-8') as f:
            self.rules = json.load(f)

        # 加载 IOC 黑名单 (无上限的 IP/域名库)
        blacklist_path = os.path.join(script_dir, "ioc_blacklist.json")
        if os.path.exists(blacklist_path):
            with open(blacklist_path, 'r', encoding='utf-8') as f:
                bl = json.load(f)
            self.blacklist_ips = set(bl.get('malicious_ips', []))
            self.blacklist_domains = set(bl.get('malicious_domains', []))
        else:
            self.blacklist_ips = set()
            self.blacklist_domains = set()

        self.findings: List[Dict] = []
        self.risk_score: int = 0
        self.files_scanned: int = 0
        self.files_skipped: int = 0
        self.suspicious_urls: List[str] = []
        self.positive_indicators: List[str] = []

        # 记录 Sentinel 自身所在目录（用于自排除）
        self._self_dir = os.path.normpath(script_dir)
        self._integrity_path = os.path.join(script_dir, '.integrity.json')

    # ----------------------------------------------------------
    #  自完整性校验：检查自身文件是否被篡改
    # ----------------------------------------------------------
    def self_integrity_check(self) -> dict:
        """
        计算 Sentinel 自身所有核心文件的 SHA256 哈希，
        与基准值对比。返回 {ok: bool, tampered: [...], missing: [...], new_baseline: bool}
        """
        current_hashes = {}
        for fname in sorted(self.SELF_EXCLUDE_FILES):
            fpath = os.path.join(self._self_dir, fname)
            if os.path.exists(fpath):
                current_hashes[fname] = self._sha256(fpath)

        # 读取基准值
        if os.path.exists(self._integrity_path):
            with open(self._integrity_path, 'r') as f:
                baseline = json.load(f)
            baseline_hashes = baseline.get('hashes', {})

            tampered = []
            missing = []
            for fname, expected_hash in baseline_hashes.items():
                if fname not in current_hashes:
                    missing.append(fname)
                elif current_hashes[fname] != expected_hash:
                    tampered.append(fname)

            if tampered or missing:
                return {'ok': False, 'tampered': tampered, 'missing': missing, 'new_baseline': False}
            return {'ok': True, 'tampered': [], 'missing': [], 'new_baseline': False}
        else:
            # 首次运行，创建基准值
            self._save_integrity(current_hashes)
            return {'ok': True, 'tampered': [], 'missing': [], 'new_baseline': True}

    def init_integrity(self):
        """重新生成基准哈希值（更新代码后调用）"""
        current_hashes = {}
        for fname in sorted(self.SELF_EXCLUDE_FILES):
            fpath = os.path.join(self._self_dir, fname)
            if os.path.exists(fpath):
                current_hashes[fname] = self._sha256(fpath)
        self._save_integrity(current_hashes)
        return current_hashes

    def _save_integrity(self, hashes: dict):
        data = {
            'created': datetime.now().isoformat(),
            'description': 'AI-Skill Sentinel 自完整性校验基准 (勿手动修改)',
            'hashes': hashes
        }
        with open(self._integrity_path, 'w') as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def _sha256(filepath: str) -> str:
        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()

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

        # 4. 后处理 - 针对 _meta.json 深度解析 (作者黑名单)
        meta_path = os.path.join(dir_path, "_meta.json")
        if os.path.exists(meta_path):
            try:
                with open(meta_path, 'r') as mf:
                    meta = json.load(mf)
                    author = meta.get('author', meta.get('uploader', ''))
                    if author:
                        # 检查作者名是否符合恶意列表
                        for rule in self.rules.get('critical_patterns', []):
                            if rule['id'] == 'C09' and re.search(rule['pattern'], str(author), re.IGNORECASE):
                                self.risk_score += rule['score']
                                self.findings.append({
                                    "level": "☠️ 致命",
                                    "file": "_meta.json",
                                    "line": 0,
                                    "rule": rule['id'],
                                    "msg": f"{rule['name']}: [{author}] 被识别为已知恶意开发者!",
                                    "score": rule['score']
                                })
            except:
                pass

    # ----------------------------------------------------------
    #  扫描单个文件
    # ----------------------------------------------------------
    def _scan_single_file(self, file_path: str):
        rel_path = os.path.basename(file_path)
        abs_path = os.path.normpath(os.path.abspath(file_path))

        # 自排除：跳过 Sentinel 自身的文件
        file_dir = os.path.dirname(abs_path)
        if file_dir == self._self_dir and rel_path in self.SELF_EXCLUDE_FILES:
            self.files_skipped += 1
            return

        self.files_scanned += 1

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

        # 2.5 IOC 黑名单查找 (基于 ioc_blacklist.json, 无上限)
        if self.blacklist_ips or self.blacklist_domains:
            # 提取文件中的所有 IP 地址
            found_ips = set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content))
            matched_ips = found_ips & self.blacklist_ips
            for ip in matched_ips:
                ip_pos = content.find(ip)
                ip_line = content[:ip_pos].count('\n') if ip_pos >= 0 else 0
                is_in_example = ip_line in code_block_lines
                is_in_cmt = ip_line in comment_lines
                score = 50 // 3 if (is_in_example or is_in_cmt) else 50
                ctx = " (已降权)" if (is_in_example or is_in_cmt) else ""
                self.risk_score += score
                self.findings.append({
                    "level": "☠️ 致命",
                    "file": rel_path,
                    "line": ip_line + 1,
                    "rule": "IOC_IP",
                    "msg": f"IOC 黑名单命中: {ip} — 已知恶意 C2/攻击基础设施{ctx}",
                    "score": score
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
        if self.files_skipped > 0:
            print(f"  {Colors.DIM}已跳过: {self.files_skipped} 个 (Sentinel 自身文件){Colors.RESET}")
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
#  辅助：检测 Ollama 是否可用
# ============================================================
def _detect_ollama() -> str:
    """检测本地 Ollama 是否运行，返回可用的模型名或空字符串"""
    try:
        import urllib.request
        req = urllib.request.Request("http://localhost:11434/api/tags")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            models = [m.get('name', '') for m in data.get('models', [])]
            for preferred in ['qwen2:72b', 'qwen2.5:72b', 'llama3:70b', 'deepseek-r1:70b']:
                if preferred in models:
                    return preferred
            return models[0] if models else ''
    except:
        return ''


def _quick_update_check():
    """快速检查 GitHub 上的规则库是否有更新"""
    try:
        import urllib.request
        script_dir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(script_dir, "rules.json"), 'r') as f:
            local_ver = json.load(f).get('version', '0')
        url = "https://raw.githubusercontent.com/berlin0212/ai-skill-sentinel/main/rules.json"
        with urllib.request.urlopen(url, timeout=5) as resp:
            remote_ver = json.loads(resp.read().decode('utf-8')).get('version', '0')
        if remote_ver != local_ver:
            print(f"  {Colors.YELLOW}🆕 发现新版本: v{local_ver} → v{remote_ver}，运行 update_rules.py 更新{Colors.RESET}")
        else:
            print(f"  {Colors.GREEN}✓ 已是最新 (v{local_ver}){Colors.RESET}")
    except:
        print(f"  {Colors.DIM}跳过 (无网络){Colors.RESET}")


# ============================================================
#  命令行入口 — 一键全自动审计
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="🛡️ AI-Skill Sentinel v2.2 — 一键 AI 技能安全审计",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用方法:
  一键全自动审计:       python3 sentinel.py /path/to/skill/
  跳过 LLM 审计:        python3 sentinel.py /path/to/skill/ --no-llm
  离线模式:             python3 sentinel.py /path/to/skill/ --offline
  仅自完整性校验:       python3 sentinel.py --self-check
  重置完整性基准:       python3 sentinel.py --init-integrity
        """
    )
    parser.add_argument("target", nargs='?', help="待扫描的文件路径或 Skill 目录")
    parser.add_argument("--rules", default="rules.json", help="规则库路径 (默认: rules.json)")
    parser.add_argument("--model", default=None, help="指定 LLM 模型 (默认: 自动检测)")
    parser.add_argument("--no-llm", action="store_true", help="跳过 LLM 深度审计")
    parser.add_argument("--no-sandbox", action="store_true", help="跳过沙盒自动生成")
    parser.add_argument("--offline", action="store_true", help="离线模式，跳过更新检查")
    parser.add_argument("--output", metavar="FILE", help="自定义 JSON 报告路径")
    parser.add_argument("--self-check", action="store_true", help="仅运行自完整性校验")
    parser.add_argument("--init-integrity", action="store_true", help="重新生成完整性基准")
    args = parser.parse_args()

    print(f"\n{Colors.BOLD}🛡️  AI-Skill Sentinel v2.2 — 一键安全审计{Colors.RESET}")
    print(f"{Colors.DIM}   \"安全不是产品，是过程。\"{Colors.RESET}")
    print(f"{'─' * 60}\n")

    sentinel = SkillSentinel(args.rules)

    # --init-integrity
    if args.init_integrity:
        hashes = sentinel.init_integrity()
        print(f"{Colors.GREEN}✅ 完整性基准已重建 ({len(hashes)} 个文件):{Colors.RESET}")
        for fname, h in sorted(hashes.items()):
            print(f"   {fname}: {h[:16]}...")
        return

    # ━━━ 步骤 1/6: 自完整性校验 ━━━
    print(f"{Colors.BOLD}[1/6] 🔒 自完整性校验{Colors.RESET}")
    integrity = sentinel.self_integrity_check()
    if integrity['new_baseline']:
        print(f"  {Colors.GREEN}首次运行，已创建基准{Colors.RESET}")
    elif not integrity['ok']:
        print(f"  {Colors.RED}⚠️ 失败！{Colors.RESET}")
        for f in integrity['tampered']:
            print(f"  {Colors.RED}  ☢️ {f} — 哈希不匹配{Colors.RESET}")
        for f in integrity['missing']:
            print(f"  {Colors.RED}  ❌ {f} — 缺失{Colors.RESET}")
        if not args.self_check:
            print(f"  {Colors.YELLOW}  继续扫描，但结果可能不可靠{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}✓ 通过{Colors.RESET}")

    if args.self_check:
        return
    if not args.target:
        parser.error("请指定待扫描的文件或目录")

    # ━━━ 步骤 2/6: 规则库更新检查 ━━━
    print(f"\n{Colors.BOLD}[2/6] 📡 规则库更新检查{Colors.RESET}")
    if args.offline:
        print(f"  {Colors.DIM}跳过 (离线模式){Colors.RESET}")
    else:
        _quick_update_check()

    # ━━━ 步骤 3/6: 深度扫描 ━━━
    print(f"\n{Colors.BOLD}[3/6] 🔍 深度扫描{Colors.RESET}")
    sentinel.scan(args.target)
    print(f"  扫描: {sentinel.files_scanned} 个文件 | 跳过: {sentinel.files_skipped} 个自身文件")

    # ━━━ 步骤 4/6: LLM 审计 ━━━
    print(f"\n{Colors.BOLD}[4/6] 🤖 LLM 深度审计{Colors.RESET}")
    use_llm = False
    skill_content = ""
    if args.no_llm:
        print(f"  {Colors.DIM}跳过 (--no-llm){Colors.RESET}")
    else:
        ollama_model = args.model or _detect_ollama()
        if ollama_model:
            print(f"  {Colors.GREEN}✓ Ollama 已连接，模型: {ollama_model}{Colors.RESET}")
            use_llm = True
            target = args.target
            if os.path.isdir(target):
                for candidate in ['SKILL.md', 'README.md']:
                    cpath = os.path.join(target, candidate)
                    if os.path.exists(cpath):
                        target = cpath
                        break
            if os.path.isfile(target):
                with open(target, 'r', encoding='utf-8', errors='ignore') as f:
                    skill_content = f.read()
        else:
            print(f"  {Colors.DIM}跳过 (Ollama 未运行){Colors.RESET}")

    # ━━━ 步骤 5/6: 审计报告 ━━━
    print(f"\n{Colors.BOLD}[5/6] 📊 审计报告{Colors.RESET}")
    sentinel.print_report(use_llm=use_llm, skill_content=skill_content)

    # ━━━ 步骤 6/6: 自动化后续 ━━━
    score = min(sentinel.risk_score, 100)
    print(f"{Colors.BOLD}[6/6] 🔧 自动化后续{Colors.RESET}")

    # 6a. JSON 报告
    if not args.output:
        if os.path.isdir(args.target):
            skill_name = os.path.basename(os.path.normpath(args.target))
        else:
            skill_name = os.path.splitext(os.path.basename(args.target))[0]
        args.output = os.path.join(
            os.path.dirname(os.path.abspath(args.target)),
            f"sentinel-report-{skill_name}.json"
        )

    report_data = {
        "version": "2.2",
        "timestamp": datetime.now().isoformat(),
        "target": os.path.abspath(args.target),
        "files_scanned": sentinel.files_scanned,
        "files_skipped": sentinel.files_skipped,
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
        "llm_audit": getattr(sentinel, '_llm_result', None),
        "integrity_check": integrity
    }
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)
    print(f"  {Colors.GREEN}📄 报告: {args.output}{Colors.RESET}")

    # 6b. 沙盒 (≥41分自动生成)
    if score >= 41 and not args.no_sandbox:
        output_dir = args.target if os.path.isdir(args.target) else os.path.dirname(args.target)
        sentinel.generate_sandbox(output_dir)
    elif score >= 41:
        print(f"  {Colors.DIM}沙盒: 跳过 (--no-sandbox){Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}🐳 沙盒: 不需要 (分数 {score} < 41){Colors.RESET}")

    print(f"\n{'═' * 60}")
    print(f"{Colors.BOLD}  ✅ 审计完成 — 风险评分: {score}/100{Colors.RESET}")
    print(f"{'═' * 60}\n")

    sys.exit(1 if score >= 65 else 0)


if __name__ == "__main__":
    main()
