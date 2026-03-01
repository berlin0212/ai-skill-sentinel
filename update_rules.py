#!/usr/bin/env python3
"""
AI-Skill Sentinel - 威胁情报自动更新器
功能:
  1. 从 GitHub 仓库拉取最新的 rules.json
  2. 从公开威胁情报源抓取恶意 IP/域名 (abuse.ch, VirusTotal)
  3. 合并到本地规则库，去重后保存
  4. 支持定时任务 (cron/launchd) 自动运行

用法:
  python3 update_rules.py                  # 从 GitHub 更新
  python3 update_rules.py --fetch-ioc      # 同时抓取公开威胁情报
  python3 update_rules.py --install-cron   # 安装每日自动更新的定时任务
"""

import os
import sys
import json
import re
from datetime import datetime
from typing import Dict, List, Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_RULES = os.path.join(SCRIPT_DIR, "rules.json")
BACKUP_DIR = os.path.join(SCRIPT_DIR, ".rules_backup")

# ============================================================
#  GitHub 仓库更新 (最可靠，零风险)
# ============================================================

# 您的 GitHub 仓库地址 (raw URL)
GITHUB_RAW_URL = "https://raw.githubusercontent.com/berlin0212/ai-skill-sentinel/main/rules.json"

def update_from_github() -> bool:
    """从您的 GitHub 仓库拉取最新 rules.json"""
    import urllib.request

    print("🔄 正在从 GitHub 检查规则库更新...")
    try:
        req = urllib.request.Request(GITHUB_RAW_URL)
        with urllib.request.urlopen(req, timeout=15) as resp:
            remote_data = json.loads(resp.read().decode('utf-8'))

        # 读取本地版本
        with open(LOCAL_RULES, 'r', encoding='utf-8') as f:
            local_data = json.load(f)

        remote_ver = remote_data.get('version', '0.0.0')
        local_ver = local_data.get('version', '0.0.0')

        if remote_ver == local_ver:
            local_count = _count_rules(local_data)
            print(f"✅ 规则库已是最新 (v{local_ver}, {local_count} 条规则)")
            return False

        # 有更新，先备份
        _backup_current()

        # 写入新版本
        with open(LOCAL_RULES, 'w', encoding='utf-8') as f:
            json.dump(remote_data, f, ensure_ascii=False, indent=4)

        remote_count = _count_rules(remote_data)
        print(f"🆕 规则库已更新: v{local_ver} → v{remote_ver} ({remote_count} 条规则)")
        return True

    except Exception as e:
        print(f"⚠️  GitHub 更新失败 (可能无网络): {e}")
        return False


# ============================================================
#  公开威胁情报抓取 (abuse.ch 恶意 IP/域名)
# ============================================================

# 公开免注册的情报源
IOC_SOURCES = {
    "abuse_ch_ipbl": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
        "desc": "abuse.ch Feodo Tracker - 银行木马 C2 IP 列表",
        "type": "ip"
    },
    "abuse_ch_urlhaus": {
        "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        "desc": "abuse.ch URLhaus - 恶意 URL (最近 24h)",
        "type": "url",
        "method": "POST"
    }
}

def fetch_ioc_feeds() -> Dict[str, List[str]]:
    """
    从公开威胁情报源抓取最新的恶意 IP 和域名。
    返回: {"malicious_ips": [...], "malicious_domains": [...]}
    """
    import urllib.request

    result = {"malicious_ips": [], "malicious_domains": []}

    # 1. abuse.ch Feodo Tracker (IP 黑名单)
    print("📡 正在从 abuse.ch 抓取恶意 C2 IP 列表...")
    try:
        url = IOC_SOURCES["abuse_ch_ipbl"]["url"]
        with urllib.request.urlopen(url, timeout=20) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            ips = [entry.get("ip_address", "") for entry in data if entry.get("ip_address")]
            # 只取最近的 50 个，避免规则库膨胀
            result["malicious_ips"] = list(set(ips))[:50]
            print(f"   ✓ 获取到 {len(result['malicious_ips'])} 个恶意 IP")
    except Exception as e:
        print(f"   ⚠️ abuse.ch IP 列表获取失败: {e}")

    # 2. 从已知 AI 安全事件中提取 (手动维护的 IOC)
    known_ai_threat_ips = [
        "91.92.242.30",     # ClawHavoc C2
        "185.196.8.51",     # AI-Agent 恶意插件 C2
        "45.133.1.20",      # Skill 供应链攻击
    ]
    result["malicious_ips"].extend(known_ai_threat_ips)
    result["malicious_ips"] = list(set(result["malicious_ips"]))

    return result


def merge_ioc_to_rules(ioc_data: Dict[str, List[str]]) -> bool:
    """将抓取到的 IOC 合并到现有规则库"""
    with open(LOCAL_RULES, 'r', encoding='utf-8') as f:
        rules = json.load(f)

    updated = False

    # 合并恶意 IP 到 critical_patterns
    if ioc_data.get("malicious_ips"):
        # 找到现有的 C2 IP 规则
        existing_c2_rule = None
        for rule in rules.get("critical_patterns", []):
            if rule["id"] == "C07":
                existing_c2_rule = rule
                break

        if existing_c2_rule:
            # 提取现有的 IP 列表
            existing_ips = set(re.findall(r'\d+\.\d+\.\d+\.\d+', existing_c2_rule['pattern']))
            new_ips = set(ioc_data["malicious_ips"]) - existing_ips

            if new_ips:
                # 将新 IP 加入正则 (用 | 分隔, 转义点号)
                all_ips = existing_ips | new_ips
                # 只保留前 30 个，防止正则过长
                ip_patterns = [ip.replace('.', '\\.') for ip in sorted(all_ips)[:30]]
                existing_c2_rule['pattern'] = '|'.join(ip_patterns)
                existing_c2_rule['desc'] = f"已知恶意 C2 服务器 IP ({len(ip_patterns)} 个)。最后更新: {datetime.now().strftime('%Y-%m-%d')}"
                updated = True
                print(f"🆕 新增 {len(new_ips)} 个恶意 IP 到规则 C07")

    if updated:
        _backup_current()
        rules['last_updated'] = datetime.now().strftime('%Y-%m-%d')
        with open(LOCAL_RULES, 'w', encoding='utf-8') as f:
            json.dump(rules, f, ensure_ascii=False, indent=4)
        print("✅ 规则库已更新并保存")

    return updated


# ============================================================
#  定时任务安装 (macOS launchd / Linux cron)
# ============================================================

def install_scheduled_update():
    """安装每日自动更新的定时任务"""
    import platform

    system = platform.system()
    script_path = os.path.abspath(__file__)

    if system == "Darwin":  # macOS
        plist_name = "com.ai-skill-sentinel.update"
        plist_path = os.path.expanduser(f"~/Library/LaunchAgents/{plist_name}.plist")
        python_path = sys.executable

        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{plist_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_path}</string>
        <string>{script_path}</string>
        <string>--fetch-ioc</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>8</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>/tmp/ai-skill-sentinel-update.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/ai-skill-sentinel-update.log</string>
</dict>
</plist>"""

        with open(plist_path, 'w') as f:
            f.write(plist_content)

        print(f"✅ macOS 定时任务已安装:")
        print(f"   文件: {plist_path}")
        print(f"   频率: 每天早上 8:00 自动更新")
        print(f"   日志: /tmp/ai-skill-sentinel-update.log")
        print(f"\n   激活命令: launchctl load {plist_path}")
        print(f"   卸载命令: launchctl unload {plist_path}")

    elif system == "Linux":
        cron_line = f"0 8 * * * {sys.executable} {script_path} --fetch-ioc >> /tmp/ai-skill-sentinel-update.log 2>&1"
        print(f"✅ 请手动添加以下 cron 任务 (crontab -e):")
        print(f"   {cron_line}")
        print(f"   频率: 每天早上 8:00")

    elif system == "Windows":
        print(f"✅ Windows 请使用任务计划程序:")
        print(f"   程序: {sys.executable}")
        print(f"   参数: {script_path} --fetch-ioc")
        print(f"   频率: 每天早上 8:00")


# ============================================================
#  辅助函数
# ============================================================

def _count_rules(data: dict) -> int:
    """统计规则总数"""
    count = 0
    for key in ['critical_patterns', 'high_patterns', 'medium_patterns', 'social_engineering']:
        count += len(data.get(key, []))
    return count

def _backup_current():
    """备份当前规则库"""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(BACKUP_DIR, f"rules_{timestamp}.json")

    import shutil
    if os.path.exists(LOCAL_RULES):
        shutil.copy2(LOCAL_RULES, backup_path)
        print(f"📦 已备份当前规则: {backup_path}")


# ============================================================
#  命令行入口
# ============================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="🔄 AI-Skill Sentinel - 威胁情报自动更新器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  从 GitHub 更新规则库:           python3 update_rules.py
  同时抓取公开威胁情报:          python3 update_rules.py --fetch-ioc
  安装每日自动更新定时任务:      python3 update_rules.py --install-cron
  只查看当前规则库状态:          python3 update_rules.py --status
        """
    )
    parser.add_argument("--fetch-ioc", action="store_true",
                        help="从公开威胁情报源 (abuse.ch) 抓取最新的恶意 IP/域名")
    parser.add_argument("--install-cron", action="store_true",
                        help="安装每日自动更新的定时任务 (macOS/Linux)")
    parser.add_argument("--status", action="store_true",
                        help="查看当前规则库状态")
    args = parser.parse_args()

    print(f"\n🔄 AI-Skill Sentinel 威胁情报更新器")
    print(f"{'─' * 45}\n")

    if args.status:
        with open(LOCAL_RULES, 'r', encoding='utf-8') as f:
            data = json.load(f)
        count = _count_rules(data)
        print(f"  版本: {data.get('version', 'N/A')}")
        print(f"  规则数: {count} 条")
        print(f"  最后更新: {data.get('last_updated', 'N/A')}")
        print(f"  文件路径: {LOCAL_RULES}")
        return

    if args.install_cron:
        install_scheduled_update()
        return

    # 1. GitHub 更新
    github_updated = update_from_github()

    # 2. 公开情报抓取
    if args.fetch_ioc:
        print()
        ioc_data = fetch_ioc_feeds()
        merge_ioc_to_rules(ioc_data)

    print(f"\n{'─' * 45}")
    print("✅ 更新完成\n")


if __name__ == "__main__":
    main()
