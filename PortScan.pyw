import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event

class PortScannerUltra:
    def __init__(self, master):
        self.master = master
        master.title("端口扫描器（增强版）By.K")
        master.geometry("800x600")
        master.minsize(700, 500)
        
        self.scanning = False
        self.stop_event = Event()
        self.results = []
        
        self.create_widgets()
        self.setup_style()

    def setup_style(self):
        """界面样式优化"""
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", padding=6, font=('微软雅黑', 9))
        style.configure("Treeview.Heading", font=('微软雅黑', 10, 'bold'))
        style.configure("Treeview", font=('Consolas', 9), rowheight=25)
        style.map("Treeview", background=[('selected', '#0078D4')])

    def create_widgets(self):
        """创建界面组件"""
        main_frame = ttk.Frame(self.master)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 输入面板
        input_frame = ttk.LabelFrame(main_frame, text="扫描配置")
        input_frame.pack(fill=tk.X, pady=5)

        # 目标地址输入
        ttk.Label(input_frame, text="目标地址：").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.target_entry = ttk.Entry(input_frame, width=40)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.target_entry.insert(0, "towin.towin.ink")

        # 端口范围输入
        ttk.Label(input_frame, text="端口范围：").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.ports_entry = ttk.Entry(input_frame, width=40)
        self.ports_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        self.ports_entry.insert(0, "20000-40000")

        # 控制按钮
        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=2, column=1, pady=10, sticky=tk.E)
        
        self.start_btn = ttk.Button(btn_frame, text="开始扫描", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="停止扫描", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = ttk.Button(btn_frame, text="导出CSV", command=self.export_results, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, padx=5)

        # 结果展示
        result_frame = ttk.LabelFrame(main_frame, text="扫描结果")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.result_tree = ttk.Treeview(
            result_frame,
            columns=('ip', 'port', 'status'),
            show='headings',
            selectmode='browse'
        )
        self.result_tree.heading('ip', text='IP地址')
        self.result_tree.heading('port', text='端口号')
        self.result_tree.heading('status', text='状态')
        self.result_tree.column('ip', width=200, anchor=tk.CENTER)
        self.result_tree.column('port', width=120, anchor=tk.CENTER)
        self.result_tree.column('status', width=150, anchor=tk.CENTER)
        self.result_tree.pack(fill=tk.BOTH, expand=True)

        # 日志区域
        log_frame = ttk.LabelFrame(main_frame, text="操作日志")
        log_frame.pack(fill=tk.BOTH, pady=5)

        self.log_area = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=('Consolas', 9),
            height=6
        )
        self.log_area.pack(fill=tk.BOTH, expand=True)

    def start_scan(self):
        """启动扫描任务"""
        try:
            target = self.target_entry.get().strip()
            self.target_ips = self.parse_target(target)
            self.port_list = self.parse_ports(self.ports_entry.get())
            
            if not self.target_ips:
                raise ValueError("无法解析目标地址")
            if not self.port_list:
                raise ValueError("无效的端口范围")

            self.scanning = True
            self.stop_event.clear()
            self.results.clear()
            self.result_tree.delete(*self.result_tree.get_children())
            self.toggle_buttons(True)
            self.log(f"[系统] 开始扫描 {len(self.target_ips)}个IP地址的{len(self.port_list)}个端口...")

            self.executor = ThreadPoolExecutor(max_workers=200)
            futures = [
                self.executor.submit(self.scan_port, ip, port)
                for ip in self.target_ips
                for port in self.port_list
                if not self.stop_event.is_set()
            ]
            
            self.master.after(100, self.process_results, futures)

        except Exception as e:
            messagebox.showerror("启动错误", str(e))
            self.toggle_buttons(False)

    def scan_port(self, ip, port):
        """执行端口扫描（增强版）"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.5)
                result = s.connect_ex((str(ip), int(port)))
                status = "开放" if result == 0 else "关闭"
                return (str(ip), str(port), status)
        except socket.gaierror:
            return (str(ip), str(port), "域名解析失败")
        except socket.timeout:
            return (str(ip), str(port), "超时")
        except ConnectionRefusedError:
            return (str(ip), str(port), "拒绝连接")
        except Exception as e:
            return (str(ip), str(port), f"错误: {str(e)}")

    def process_results(self, futures):
        """处理扫描结果（最终修复版）"""
        open_count = 0
        total = len(futures)
        
        for i, future in enumerate(as_completed(futures)):
            if self.stop_event.is_set():
                break
            
            try:
                result = future.result()
                # 格式验证
                if len(result) != 3 or not all(isinstance(x, str) for x in result):
                    self.log(f"[错误] 无效结果格式: {result}")
                    continue
                
                ip, port_str, status = result
                self.results.append(result)
                self.result_tree.insert('', tk.END, values=result)
                
                # 精确统计逻辑
                if status.strip().lower() == "开放":
                    open_count += 1
                    self.log(f"发现开放端口：{ip}:{port_str}")
                
                # 进度更新（每5%或最后1个）
                current_progress = i + 1
                if current_progress % max(1, total//20) == 0 or current_progress == total:
                    progress_percent = current_progress / total * 100
                    self.log(f"[进度] 已完成 {current_progress}/{total} ({progress_percent:.1f}%)")
                    self.log_area.see(tk.END)
                    self.master.update_idletasks()

            except Exception as e:
                self.log(f"[处理错误] {str(e)}")
                continue

        # 最终状态更新
        self.scanning = False
        self.toggle_buttons(False)
        self.log(f"[系统] 扫描完成，共发现 {open_count} 个开放端口")
        self.export_btn.config(state=tk.NORMAL if open_count > 0 else tk.DISABLED)
        
        # 控制台验证输出
        print(f"统计验证：总任务数={total} 开放数={open_count}")

    def toggle_buttons(self, scanning):
        """切换按钮状态"""
        state = tk.DISABLED if scanning else tk.NORMAL
        self.start_btn.config(state=state)
        self.stop_btn.config(state=tk.NORMAL if scanning else tk.DISABLED)
        self.export_btn.config(state=tk.NORMAL if self.results else tk.DISABLED)

    def stop_scan(self):
        """停止扫描（增强版）"""
        if self.scanning:
            self.log("[系统] 正在停止扫描...")
            self.stop_event.set()
            self.executor.shutdown(wait=False, cancel_futures=True)
            self.scanning = False
            self.toggle_buttons(False)

    def export_results(self):
        """导出结果到CSV（增强版）"""
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV 文件", "*.csv")]
            )
            if not file_path:
                return

            # 过滤有效开放端口
            valid_entries = []
            for entry in self.results:
                if len(entry) != 3:
                    continue
                ip, port, status = entry
                if status.strip().lower() == "开放" and port.isdigit():
                    valid_entries.append(f"{ip},{port},{status}")
            
            if not valid_entries:
                messagebox.showwarning("导出失败", "没有可导出的开放端口")
                return

            # 写入CSV文件
            with open(file_path, 'w', encoding='utf-8-sig') as f:
                f.write("IP地址,端口号,状态\n")
                f.write('\n'.join(valid_entries))

            self.log(f"[系统] 成功导出 {len(valid_entries)} 条记录到 {file_path}")
            messagebox.showinfo("导出成功", "CSV文件保存成功")
        except Exception as e:
            messagebox.showerror("导出失败", f"错误: {str(e)}")

    def log(self, message):
        """记录日志（线程安全版）"""
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.master.update_idletasks()

    def parse_target(self, target_str):
        """解析目标地址（增强版）"""
        try:
            # 处理域名解析
            if any(c.isalpha() for c in target_str):
                self.log(f"[解析] 正在解析域名: {target_str}")
                try:
                    info_list = socket.getaddrinfo(target_str, None, family=socket.AF_INET)
                    ips = set()
                    for info in info_list:
                        ip = info[4][0]  # 提取IPv4地址
                        ips.add(ip)
                    if not ips:
                        raise ValueError("未解析到有效IPv4地址")
                    self.log(f"[解析] 解析到{len(ips)}个IP地址")
                    return list(ips)
                except socket.gaierror as e:
                    raise ValueError(f"域名解析失败: {str(e)}")

            # 处理IP范围
            if '-' in target_str:
                start, end = target_str.split('-', 1)
                try:
                    start_ip = ipaddress.IPv4Address(start.strip())
                    end_ip = ipaddress.IPv4Address(end.strip())
                    return [str(ipaddress.IPv4Address(ip)) 
                           for ip in range(int(start_ip), int(end_ip)+1)]
                except ipaddress.AddressValueError:
                    raise ValueError("IP范围格式错误")
            
            # 处理CIDR表示法
            if '/' in target_str:
                network = ipaddress.IPv4Network(target_str, strict=False)
                return [str(host) for host in network.hosts()]
            
            # 单个IP地址
            return [str(ipaddress.IPv4Address(target_str.strip()))]
        
        except (socket.gaierror, ipaddress.AddressValueError) as e:
            messagebox.showerror("解析错误", f"无法解析目标地址: {str(e)}")
            return []

    def parse_ports(self, port_str):
        """解析端口范围（增强版）"""
        ports = set()
        for part in port_str.split(','):
            part = part.strip()
            if not part:
                continue
                
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    if 1 <= start <= end <= 65535:
                        ports.update(range(start, end+1))
                    else:
                        self.log(f"[警告] 无效端口范围: {part}")
                except ValueError:
                    self.log(f"[警告] 非法端口定义: {part}")
            elif part.isdigit():
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
                else:
                    self.log(f"[警告] 端口越界: {port}")
            else:
                self.log(f"[警告] 非法端口格式: {part}")
        return sorted(ports) if ports else None

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerUltra(root)
    root.mainloop()