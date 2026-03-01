import os
import re
import json
import argparse
from typing import List, Dict

class SkillSentinel:
    def __init__(self, rules_file: str):
        # 默认脚本目录
        script_dir = os.path.dirname(os.path.abspath(__file__))
        rules_path = os.path.join(script_dir, rules_file)
        
        with open(rules_path, 'r', encoding='utf-8') as f:
            self.rules = json.load(f)
        self.report = {"risk_score": 0, "findings": []}

    def scan_file(self, file_path: str):
        print(f"🔍 正在深度扫描目标 Skill: {file_path} ...")
        if not os.path.exists(file_path):
            print(f"❌ 错误: 找不到文件 {file_path}")
            return
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
            
            # 1. 静态关键模式扫描
            for rule in self.rules['critical_patterns']:
                matches = re.finditer(rule['pattern'], content, re.IGNORECASE)
                for match in matches:
                    # 获取所在行号
                    line_num = content[:match.start()].count('\n') + 1
                    self.report['risk_score'] += 35
                    self.report['findings'].append(f"【高危】{rule['name']}(第{line_num}行): {rule['desc']}")

            # 2. 行为分析：外联域名审计
            urls = re.findall(r'https?://[^\s)\]\'"]+', content)
            unique_urls = set(urls)
            for url in unique_urls:
                is_safe = any(domain in url for domain in self.rules['permission_whitelist']['safe_domains'])
                if not is_safe:
                    self.report['risk_score'] += 15
                    self.report['findings'].append(f"【⚠️】未知外联域名: {url} (请手动核查该地址是否可信)")

            # 3. 本地模型审计占位
            # if self.report['risk_score'] > 0:
            #     print("💡 建议: 当 128G 电脑到货后，可启用 Llama-3-70B 进行逻辑语义深度审计。")

    def print_report(self):
        print("\n" + "═"*50)
        print(f"        🛡️  AI-SKILL SENTINEL 审计报告")
        print("═"*50)
        
        score = min(self.report['risk_score'], 100)
        if score < 30:
            status = "🟢 安全 (建议人工浏览代码)"
        elif score < 65:
            status = "🟡 中风险 (必须使用 Docker 隔离)"
        else:
            status = "🔴 极高风险 (检测到恶意指纹，严禁安装)"
            
        print(f"【最终结论】 {status}")
        print(f"【风险评分】 {score}/100")
        print("-" * 50)
        
        if not self.report['findings']:
            print("\n✨ 恭喜！未检测到任何已知的恶意模式或可疑行为。")
        else:
            print("\n详细风险发现:")
            for item in sorted(list(set(self.report['findings']))):
                print(f" ✘ {item}")
        
        print("\n" + "═"*50)
        if score >= 65:
            print("🛑 警告: 该 Skill 极可能包含勒索软件或数据窃取脚本。")
        print("🛡️  建议在 ~/Downloads/ai-skill-sentinel 目录下查看守护脚本。")
        print("═"*50 + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Skill Sentinel - 本地智能体安全防火墙")
    parser.add_argument("target", help="待扫描的 SKILL.md 文件路径")
    parser.add_argument("--rules", default="rules.json", help="规则库路径")
    args = parser.parse_args()

    sentinel = SkillSentinel(args.rules)
    sentinel.scan_file(args.target)
    sentinel.print_report()
