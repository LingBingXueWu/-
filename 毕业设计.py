#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基于Python的Web应用安全测试框架 - 独立图形界面版
作者：李家赫  吉林师范大学数学与计算机学院
功能：SQL注入检测 | XSS检测 | 命令注入检测 | 路径遍历检测
"""

import re
import time
import json
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from dataclasses import field as dataclass_field

import requests
from bs4 import BeautifulSoup

# 禁用SSL警告
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ==================== 数据模型 ====================
@dataclass
class Vulnerability:  # 漏洞数据类 - 存储发现的漏洞信息
    """漏洞数据模型"""
    url: str  # 漏洞所在URL
    vuln_type: str  # 漏洞类型 (SQL注入/XSS/命令注入)
    parameter: str  # 存在漏洞的参数名
    payload: str  # 攻击载荷
    evidence: str  # 漏洞证据
    severity: str  # 严重等级 (critical/high/medium/low)
    timestamp: str = dataclass_field(default_factory=lambda: datetime.now().strftime('%Y-%m-%d %H:%M:%S'))


# ==================== 信息收集模块 ====================
class Crawler:  # 爬虫引擎 - 收集目标页面的URL、表单和参数
    """基于广度优先的Web爬虫"""

    def __init__(self, base_url: str, max_pages: int = 50):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.visited = set()  # 已访问URL集合
        self.url_queue = []  # 待访问URL队列
        self.forms = []  # 发现的表单列表
        self.params = set()  # 收集的参数集合
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def crawl(self, progress_callback=None) -> dict:
        """执行爬取，返回收集结果"""
        self.url_queue.append(self.base_url)

        while self.url_queue and len(self.visited) < self.max_pages:
            url = self.url_queue.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)

            if progress_callback:
                progress_callback(len(self.visited), self.max_pages)

            try:
                resp = self.session.get(url, timeout=10, verify=False)
                soup = BeautifulSoup(resp.text, 'html.parser')

                # 提取所有链接
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(url, link['href'])
                    if self.domain in full_url and full_url not in self.visited:
                        self.url_queue.append(full_url)

                # 提取所有表单
                for form in soup.find_all('form'):
                    form_info = {
                        'action': urljoin(url, form.get('action', '')),
                        'method': form.get('method', 'get').upper(),
                        'inputs': []
                    }
                    for inp in form.find_all(['input', 'textarea']):
                        if inp.get('name'):
                            form_info['inputs'].append({
                                'name': inp.get('name'),
                                'type': inp.get('type', 'text'),
                                'value': inp.get('value', '')
                            })
                    if form_info['inputs']:
                        self.forms.append(form_info)

                # 提取URL参数
                parsed = urlparse(url)
                if parsed.query:
                    for param in parse_qs(parsed.query).keys():
                        self.params.add(param)

                time.sleep(0.3)  # 延迟避免过载
            except Exception as e:
                continue

        return {
            'pages': list(self.visited),
            'forms': self.forms,
            'params': list(self.params)
        }


# ==================== 漏洞检测插件 ====================
class SQLInjectionDetector:  # SQL注入检测器 - 支持错误注入和时间盲注
    """SQL注入漏洞检测插件"""
    name = "SQL注入"
    severity = "high"

    def __init__(self):
        self.payloads = [
            ("'", "error"), ('"', "error"),
            ("' OR '1'='1", "bool"),
            ("' OR '1'='1' -- ", "bool"),
            ("' AND SLEEP(5)-- ", "time"),
            ("' OR SLEEP(5)-- ", "time"),
            ("1' AND SLEEP(5)-- ", "time"),
            ("'; SELECT SLEEP(5)-- ", "time"),
        ]
        self.error_patterns = [
            r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQLSyntaxErrorException",
            r"PostgreSQL.*ERROR", r"ORA-\d{5}", r"Oracle error",
            r"Microsoft.*ODBC.*SQL Server", r"SqlException",
            r"Unclosed quotation mark", r"valid MySQL result"
        ]

    def check(self, url: str, params: dict, method: str = 'GET', callback=None) -> Optional[Vulnerability]:
        """检测SQL注入漏洞"""
        for param, value in params.items():
            for payload, ptype in self.payloads:
                if callback:
                    callback(f"测试SQL注入: {param} -> {payload[:30]}...")

                test_params = params.copy()
                test_params[param] = str(value) + payload

                try:
                    if method == 'GET':
                        resp = requests.get(url, params=test_params, timeout=10, verify=False)
                    else:
                        resp = requests.post(url, data=test_params, timeout=10, verify=False)

                    # 错误注入检测
                    if ptype == "error":
                        for pattern in self.error_patterns:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                return Vulnerability(
                                    url=url, vuln_type=self.name, parameter=param,
                                    payload=payload, evidence=f"数据库错误: {pattern}",
                                    severity=self.severity
                                )

                    # 时间盲注检测
                    if ptype == "time" and "SLEEP" in payload:
                        start = time.time()
                        if method == 'GET':
                            requests.get(url, params=test_params, timeout=10, verify=False)
                        else:
                            requests.post(url, data=test_params, timeout=10, verify=False)
                        elapsed = time.time() - start
                        if elapsed >= 4:
                            return Vulnerability(
                                url=url, vuln_type=self.name, parameter=param,
                                payload=payload, evidence=f"时间延迟 {elapsed:.1f}秒",
                                severity=self.severity
                            )
                except Exception:
                    continue
        return None


class XSSDetector:  # XSS检测器 - 反射型XSS检测
    """跨站脚本(XSS)漏洞检测插件"""
    name = "XSS"
    severity = "medium"

    def __init__(self):
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert('XSS')",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "';alert('XSS');//",
            "\"><script>alert(1)</script>",
            "><script>alert(1)</script>",
        ]

    def check(self, url: str, params: dict, method: str = 'GET', callback=None) -> Optional[Vulnerability]:
        """检测XSS漏洞"""
        for param, value in params.items():
            for payload in self.payloads:
                if callback:
                    callback(f"测试XSS: {param} -> {payload[:30]}...")

                test_params = params.copy()
                test_params[param] = str(value) + payload

                try:
                    if method == 'GET':
                        resp = requests.get(url, params=test_params, timeout=10, verify=False)
                    else:
                        resp = requests.post(url, data=test_params, timeout=10, verify=False)

                    # 检查payload是否未编码返回
                    if payload in resp.text:
                        encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
                        if encoded not in resp.text:
                            return Vulnerability(
                                url=url, vuln_type=self.name, parameter=param,
                                payload=payload, evidence=f"Payload未转义返回: {payload[:50]}",
                                severity=self.severity
                            )
                except Exception:
                    continue
        return None


class CommandInjector:  # 命令注入检测器 - 支持时间盲注和输出检测
    """命令注入漏洞检测插件"""
    name = "命令注入"
    severity = "critical"

    def __init__(self):
        self.payloads = [
            ("; sleep 5", "time"), ("| sleep 5", "time"),
            ("&& sleep 5", "time"), ("|| sleep 5", "time"),
            ("`sleep 5`", "time"), ("$(sleep 5)", "time"),
            ("; echo test", "output"), ("| whoami", "output"),
            ("; whoami", "output"), ("| cat /etc/passwd", "output"),
        ]
        self.output_patterns = [
            r"root:.*:0:0", r"uid=\d+", r"Administrator",
            r"test", r"bin:.*:bin", r"nt authority\\system"
        ]

    def check(self, url: str, params: dict, method: str = 'GET', callback=None) -> Optional[Vulnerability]:
        """检测命令注入漏洞"""
        for param, value in params.items():
            for payload, ptype in self.payloads:
                if callback:
                    callback(f"测试命令注入: {param} -> {payload[:30]}...")

                test_params = params.copy()
                test_params[param] = str(value) + payload

                try:
                    start = time.time()
                    if method == 'GET':
                        resp = requests.get(url, params=test_params, timeout=10, verify=False)
                    else:
                        resp = requests.post(url, data=test_params, timeout=10, verify=False)
                    elapsed = time.time() - start

                    # 时间盲注检测
                    if ptype == "time" and elapsed >= 4:
                        return Vulnerability(
                            url=url, vuln_type=self.name, parameter=param,
                            payload=payload, evidence=f"命令执行延迟 {elapsed:.1f}秒",
                            severity=self.severity
                        )

                    # 输出检测
                    if ptype == "output":
                        for pattern in self.output_patterns:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                return Vulnerability(
                                    url=url, vuln_type=self.name, parameter=param,
                                    payload=payload, evidence=f"命令输出: {pattern}",
                                    severity=self.severity
                                )
                except Exception:
                    continue
        return None


class PathTraversalDetector:  # 路径遍历检测器
    """路径遍历漏洞检测插件"""
    name = "路径遍历"
    severity = "high"

    def __init__(self):
        self.payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "....//....//....//etc/passwd",
        ]
        self.patterns = ["root:x:", "daemon:x:", "[extensions]", "[fonts]"]

    def check(self, url: str, params: dict, method: str = 'GET', callback=None) -> Optional[Vulnerability]:
        """检测路径遍历漏洞"""
        for param, value in params.items():
            for payload in self.payloads:
                test_params = params.copy()
                test_params[param] = str(value) + payload

                try:
                    if method == 'GET':
                        resp = requests.get(url, params=test_params, timeout=10, verify=False)
                    else:
                        resp = requests.post(url, data=test_params, timeout=10, verify=False)

                    for pattern in self.patterns:
                        if pattern in resp.text:
                            return Vulnerability(
                                url=url, vuln_type=self.name, parameter=param,
                                payload=payload, evidence=f"敏感文件内容: {pattern}",
                                severity=self.severity
                            )
                except Exception:
                    continue
        return None


# ==================== 核心调度器 ====================
class ScanScheduler:  # 扫描调度器 - 管理任务、并发控制和进度跟踪
    """扫描任务调度器"""

    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.tasks = {}
        self.plugins = [
            SQLInjectionDetector(),
            XSSDetector(),
            CommandInjector(),
            PathTraversalDetector()
        ]

    def start_scan(self, target_url: str, callback=None) -> str:
        """启动扫描任务，返回任务ID"""
        task_id = f"scan_{int(time.time())}"
        self.tasks[task_id] = {
            'status': 'running',
            'progress': 0,
            'vulns': [],
            'message': '任务已创建'
        }

        # 异步执行扫描
        self.executor.submit(self._run_scan, task_id, target_url, callback)
        return task_id

    def _run_scan(self, task_id: str, target_url: str, callback=None):
        """执行扫描流程（在后台线程中运行）"""
        vulns = []

        # 阶段1：信息收集 (进度10%)
        self._update_task(task_id, 10, 'running', "正在收集目标信息...")
        if callback:
            callback('progress', 10, "正在爬取网站结构...")

        crawler = Crawler(target_url, max_pages=50)
        result = crawler.crawl(lambda curr, total: callback('crawl', curr, total) if callback else None)

        # 阶段2：漏洞扫描
        total_targets = len(result['pages']) + len(result['forms'])
        processed = 0

        if callback:
            callback('log', f"[信息] 发现 {len(result['pages'])} 个页面, {len(result['forms'])} 个表单")

        # 扫描页面URL参数
        for page in result['pages']:
            if self.tasks[task_id].get('cancelled', False):
                self._update_task(task_id, 0, 'cancelled', "任务已取消")
                return

            parsed = urlparse(page)
            if parsed.query:
                params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                for plugin in self.plugins:
                    vuln = plugin.check(page, params, 'GET',
                                        lambda msg: callback('log', f"[测试] {msg}") if callback else None)
                    if vuln:
                        vulns.append(vuln)
                        if callback:
                            callback('vuln', vuln)

            processed += 1
            progress = 30 + int(processed / total_targets * 60)
            self._update_task(task_id, progress, 'running', f"扫描进度: {processed}/{total_targets}")
            if callback:
                callback('progress', progress, f"扫描中... {processed}/{total_targets}")

        # 扫描表单参数
        for form in result['forms']:
            if self.tasks[task_id].get('cancelled', False):
                self._update_task(task_id, 0, 'cancelled', "任务已取消")
                return

            params = {inp['name']: inp.get('value', 'test') for inp in form['inputs']}
            for plugin in self.plugins:
                vuln = plugin.check(form['action'], params, form['method'],
                                    lambda msg: callback('log', f"[测试] {msg}") if callback else None)
                if vuln:
                    vulns.append(vuln)
                    if callback:
                        callback('vuln', vuln)

            processed += 1
            progress = 30 + int(processed / total_targets * 60)
            self._update_task(task_id, progress, 'running', f"扫描进度: {processed}/{total_targets}")
            if callback:
                callback('progress', progress, f"扫描中... {processed}/{total_targets}")

        # 阶段3：完成
        severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for v in vulns:
            severity_count[v.severity] += 1

        self._update_task(task_id, 100, 'completed', f"扫描完成，发现{len(vulns)}个漏洞")
        self.tasks[task_id]['vulns'] = vulns
        self.tasks[task_id]['summary'] = severity_count

        if callback:
            callback('complete', vulns, severity_count)

    def _update_task(self, task_id: str, progress: int, status: str, message: str):
        """更新任务状态"""
        if task_id in self.tasks:
            self.tasks[task_id].update({'progress': progress, 'status': status, 'message': message})

    def get_status(self, task_id: str) -> dict:
        """获取任务状态"""
        return self.tasks.get(task_id, {'status': 'not_found'})

    def cancel_scan(self, task_id: str):
        """取消扫描任务"""
        if task_id in self.tasks and self.tasks[task_id]['status'] == 'running':
            self.tasks[task_id]['cancelled'] = True


# ==================== 图形界面 ====================
class SecurityScannerGUI:  # 主窗口类 - 构建图形用户界面
    """Web安全测试框架图形界面"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Web应用安全测试框架 v1.0")
        self.root.geometry("1100x750")
        self.root.resizable(True, True)

        # 设置样式
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # 全局变量
        self.scanner = None
        self.current_task_id = None
        self.vulnerabilities = []

        # 构建界面
        self._build_ui()

        # 初始化扫描器
        self.scheduler = ScanScheduler()

    def _build_ui(self):
        """构建用户界面"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # ========== 顶部输入区域 ==========
        input_frame = ttk.LabelFrame(main_frame, text="目标配置", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(input_frame, text="目标URL:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.url_entry = ttk.Entry(input_frame, width=60)
        self.url_entry.grid(row=0, column=1, padx=(0, 10), sticky=tk.W + tk.E)
        self.url_entry.insert(0, "http://testphp.vulnweb.com")

        self.scan_btn = ttk.Button(input_frame, text="开始扫描", command=self.start_scan)
        self.scan_btn.grid(row=0, column=2, padx=(0, 5))

        self.cancel_btn = ttk.Button(input_frame, text="取消扫描", command=self.cancel_scan, state=tk.DISABLED)
        self.cancel_btn.grid(row=0, column=3)

        # 进度条
        self.progress_var = tk.IntVar()
        self.progress_bar = ttk.Progressbar(input_frame, variable=self.progress_var, maximum=100, length=300)
        self.progress_bar.grid(row=1, column=0, columnspan=4, sticky=tk.W + tk.E, pady=(10, 0))

        self.status_label = ttk.Label(input_frame, text="就绪")
        self.status_label.grid(row=2, column=0, columnspan=4, sticky=tk.W, pady=(5, 0))

        input_frame.columnconfigure(1, weight=1)

        # ========== 中间区域（漏洞列表 + 日志）==========
        middle_frame = ttk.Frame(main_frame)
        middle_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # 左侧：漏洞列表
        vuln_frame = ttk.LabelFrame(middle_frame, text="发现的漏洞", padding="5")
        vuln_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        # 树形表格
        columns = ('类型', 'URL', '参数', '严重等级', '时间')
        self.tree = ttk.Treeview(vuln_frame, columns=columns, show='tree headings', height=15)

        self.tree.heading('#0', text='#')
        self.tree.heading('类型', text='漏洞类型')
        self.tree.heading('URL', text='URL')
        self.tree.heading('参数', text='参数')
        self.tree.heading('严重等级', text='严重等级')
        self.tree.heading('时间', text='发现时间')

        self.tree.column('#0', width=40)
        self.tree.column('类型', width=100)
        self.tree.column('URL', width=300)
        self.tree.column('参数', width=100)
        self.tree.column('严重等级', width=80)
        self.tree.column('时间', width=130)

        # 滚动条
        vsb = ttk.Scrollbar(vuln_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # 绑定选择事件
        self.tree.bind('<<TreeviewSelect>>', self.on_vuln_select)

        # 右侧：日志区域
        log_frame = ttk.LabelFrame(middle_frame, text="扫描日志", padding="5")
        log_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=45, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # ========== 底部详情区域 ==========
        detail_frame = ttk.LabelFrame(main_frame, text="漏洞详情", padding="10")
        detail_frame.pack(fill=tk.X)

        self.detail_text = scrolledtext.ScrolledText(detail_frame, height=6, wrap=tk.WORD)
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        # ========== 底部按钮区域 ==========
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(fill=tk.X, pady=(10, 0))

        self.export_btn = ttk.Button(bottom_frame, text="导出报告 (HTML)", command=self.export_report,
                                     state=tk.DISABLED)
        self.export_btn.pack(side=tk.RIGHT, padx=(5, 0))

        self.clear_btn = ttk.Button(bottom_frame, text="清空结果", command=self.clear_results)
        self.clear_btn.pack(side=tk.RIGHT)

        # 配置网格权重
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)

    def log(self, message: str):
        """添加日志消息"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)

    def add_vulnerability(self, vuln: Vulnerability):
        """添加漏洞到列表"""
        self.vulnerabilities.append(vuln)

        # 设置标签样式
        severity_tags = {
            'critical': ('critical',),
            'high': ('high',),
            'medium': ('medium',)
        }

        item = self.tree.insert('', 'end', text=str(len(self.vulnerabilities)),
                                values=(vuln.vuln_type, vuln.url[:60], vuln.parameter, vuln.severity, vuln.timestamp))

        # 设置颜色
        if vuln.severity == 'critical':
            self.tree.tag_configure('critical', background='#ffcccc')
            self.tree.item(item, tags=('critical',))
        elif vuln.severity == 'high':
            self.tree.tag_configure('high', background='#ffe6cc')
            self.tree.item(item, tags=('high',))
        elif vuln.severity == 'medium':
            self.tree.tag_configure('medium', background='#ffffcc')
            self.tree.item(item, tags=('medium',))

        self.log(f"[!] 发现 {vuln.vuln_type} 漏洞 @ {vuln.parameter} (严重程度: {vuln.severity})")

    def on_vuln_select(self, event):
        """漏洞选择事件 - 显示详情"""
        selection = self.tree.selection()
        if selection:
            idx = int(self.tree.item(selection[0], 'text')) - 1
            if 0 <= idx < len(self.vulnerabilities):
                vuln = self.vulnerabilities[idx]
                detail = f"""
═══════════════════════════════════════════════════════════════
漏洞类型: {vuln.vuln_type}
严重等级: {vuln.severity}
发现时间: {vuln.timestamp}
URL: {vuln.url}
参数名: {vuln.parameter}
攻击载荷: {vuln.payload}
证据: {vuln.evidence}
═══════════════════════════════════════════════════════════════
修复建议: 
  - SQL注入: 使用参数化查询/预编译语句
  - XSS: 对输出进行HTML编码，设置CSP策略
  - 命令注入: 避免使用系统命令，严格过滤特殊字符
  - 路径遍历: 使用路径白名单验证
                """
                self.detail_text.delete(1.0, tk.END)
                self.detail_text.insert(1.0, detail)

    def start_scan(self):
        """开始扫描"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("错误", "请输入目标URL")
            return

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, url)

        # 清空之前的结果
        self.clear_results()

        # 禁用开始按钮，启用取消按钮
        self.scan_btn.config(state=tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.DISABLED)

        self.log(f"[+] 开始扫描目标: {url}")

        # 回调函数
        def on_callback(event_type, *args):
            def update():
                if event_type == 'progress':
                    self.progress_var.set(args[0])
                    self.status_label.config(text=args[1])
                elif event_type == 'crawl':
                    self.status_label.config(text=f"爬取中... {args[0]}/{args[1]} 页面")
                elif event_type == 'log':
                    self.log(args[0])
                elif event_type == 'vuln':
                    self.add_vulnerability(args[0])
                elif event_type == 'complete':
                    vulns, summary = args
                    self.progress_var.set(100)
                    self.status_label.config(text=f"扫描完成！发现 {len(vulns)} 个漏洞")
                    self.scan_btn.config(state=tk.NORMAL)
                    self.cancel_btn.config(state=tk.DISABLED)
                    if vulns:
                        self.export_btn.config(state=tk.NORMAL)
                    self.log(
                        f"[✓] 扫描完成! 严重: {summary.get('critical', 0)} 高危: {summary.get('high', 0)} 中危: {summary.get('medium', 0)}")

            self.root.after(0, update)

        # 启动扫描
        self.current_task_id = self.scheduler.start_scan(url, on_callback)

    def cancel_scan(self):
        """取消扫描"""
        if self.current_task_id:
            self.scheduler.cancel_scan(self.current_task_id)
            self.log("[!] 正在取消扫描...")
            self.status_label.config(text="正在取消...")
            self.scan_btn.config(state=tk.NORMAL)
            self.cancel_btn.config(state=tk.DISABLED)

    def export_report(self):
        """导出HTML报告"""
        if not self.vulnerabilities:
            messagebox.showwarning("警告", "没有漏洞数据可导出")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML文件", "*.html"), ("所有文件", "*.*")],
            initialfile=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )

        if file_path:
            html = self._generate_html_report()
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html)
            self.log(f"[+] 报告已导出: {file_path}")
            messagebox.showinfo("成功", f"报告已保存到:\n{file_path}")

    def _generate_html_report(self) -> str:
        """生成HTML报告"""
        target_url = self.url_entry.get()

        severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for v in self.vulnerabilities:
            severity_count[v.severity] = severity_count.get(v.severity, 0) + 1

        html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>Web安全测试报告 - {target_url}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: auto; background: white; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .stats {{ display: flex; justify-content: center; gap: 20px; padding: 20px; background: #f8f9fa; }}
        .stat {{ text-align: center; padding: 15px; background: white; border-radius: 8px; min-width: 100px; }}
        .stat-number {{ font-size: 28px; font-weight: bold; }}
        .stat-critical {{ color: #dc3545; }} .stat-high {{ color: #fd7e14; }} .stat-medium {{ color: #ffc107; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; }}
        .critical-row {{ background: #ffebee; }}
        .high-row {{ background: #fff3e0; }}
        .medium-row {{ background: #fff9c4; }}
        .footer {{ text-align: center; padding: 20px; color: #666; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Web应用安全测试报告</h1>
        <p>目标: {target_url}</p>
        <p>生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    <div class="stats">
        <div class="stat"><div class="stat-number">{len(self.vulnerabilities)}</div><div>总漏洞数</div></div>
        <div class="stat"><div class="stat-number stat-critical">{severity_count.get('critical', 0)}</div><div>严重</div></div>
        <div class="stat"><div class="stat-number stat-high">{severity_count.get('high', 0)}</div><div>高危</div></div>
        <div class="stat"><div class="stat-number stat-medium">{severity_count.get('medium', 0)}</div><div>中危</div></div>
    </div>
    <div style="padding: 20px;">
        <h2>漏洞详情</h2>
        <table>
            <thead><tr><th>#</th><th>漏洞类型</th><th>URL</th><th>参数</th><th>严重等级</th><th>Payload</th></tr></thead>
            <tbody>
'''

        for i, v in enumerate(self.vulnerabilities):
            row_class = f"{v.severity}-row" if v.severity in ['critical', 'high', 'medium'] else ''
            html += f'''
                <tr class="{row_class}">
                    <td>{i + 1}</td>
                    <td>{v.vuln_type}</td>
                    <td>{v.url[:80]}</td>
                    <td>{v.parameter}</td>
                    <td>{v.severity}</td>
                    <td><code>{v.payload[:60]}</code></td>
                </tr>
                <tr class="{row_class}"><td colspan="6" style="background:#fafafa;"><strong>证据:</strong> {v.evidence}</td></tr>
'''

        html += f'''
            </tbody>
        </table>
    </div>
    <div class="footer">
        <p>本报告由Web应用安全测试框架自动生成 | 李家赫 吉林师范大学数学与计算机学院</p>
    </div>
</div>
</body>
</html>'''

        return html

    def clear_results(self):
        """清空所有结果"""
        self.vulnerabilities = []
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.detail_text.delete(1.0, tk.END)
        self.log_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        self.status_label.config(text="就绪")
        self.export_btn.config(state=tk.DISABLED)

    def run(self):
        """运行主循环"""
        self.root.mainloop()


# ==================== 主程序入口 ====================
def main():
    """主函数"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║     Web应用安全测试框架                                         ║
║     功能：SQL注入检测 | XSS检测 | 命令注入检测 | 路径遍历检测        ║
╚══════════════════════════════════════════════════════════════╝
    """)

    # 启动图形界面
    app = SecurityScannerGUI()
    app.run()


if __name__ == "__main__":
    main()