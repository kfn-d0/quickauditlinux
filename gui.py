import customtkinter as ctk
import threading
import time
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from ssh_client import SSHClient
from metrics import MetricsCollector

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class VMDashboard(ctk.CTkFrame):
    def __init__(self, master, tab_name_update_callback=None, **kwargs):
        super().__init__(master, **kwargs)
        
        self.ssh = SSHClient()
        self.metrics = MetricsCollector(self.ssh)
        self.is_monitoring = False
        self.update_tab_name_callback = tab_name_update_callback
        
        self.x_data = list(range(60))
        self.cpu_data = [0] * 60
        self.ram_data = [0] * 60
        self.disk_data = [0] * 60

        self.setup_ui()

    def setup_ui(self):
        self.conn_frame = ctk.CTkFrame(self)
        self.conn_frame.pack(fill="x", padx=10, pady=5)
        
        self.ip_entry = ctk.CTkEntry(self.conn_frame, placeholder_text="IP", width=120)
        self.ip_entry.pack(side="left", padx=5, pady=5)
        
        self.port_entry = ctk.CTkEntry(self.conn_frame, placeholder_text="Port (default: 22)", width=120)
        self.port_entry.pack(side="left", padx=5, pady=5)
        
        self.user_entry = ctk.CTkEntry(self.conn_frame, placeholder_text="Username", width=100)
        self.user_entry.pack(side="left", padx=5, pady=5)
        
        self.pass_entry = ctk.CTkEntry(self.conn_frame, placeholder_text="Password", show="*", width=100)
        self.pass_entry.pack(side="left", padx=5, pady=5)
        
        self.connect_btn = ctk.CTkButton(self.conn_frame, text="Connect", command=self.toggle_connection, width=100)
        self.connect_btn.pack(side="left", padx=5, pady=5)
        
        self.status_label = ctk.CTkLabel(self.conn_frame, text="Disconnected", text_color="red")
        self.status_label.pack(side="left", padx=10, pady=5)
        
        self.scroll_frame = ctk.CTkScrollableFrame(self)
        self.scroll_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.scroll_frame.grid_columnconfigure((0, 1), weight=1)
        
        self.monitor_frame = ctk.CTkFrame(self.scroll_frame)
        self.monitor_frame.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)
        
        self.monitor_title = ctk.CTkLabel(self.monitor_frame, text="Real-time Monitoring", font=ctk.CTkFont(size=16, weight="bold"))
        self.monitor_title.pack(pady=10)
        
        self.fig = Figure(figsize=(8, 3), dpi=100)
        self.fig.patch.set_facecolor('#2b2b2b')
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor('#2b2b2b')
        self.ax.tick_params(colors='white')
        self.ax.spines['bottom'].set_color('white')
        self.ax.spines['left'].set_color('white')
        self.ax.spines['top'].set_visible(False)
        self.ax.spines['right'].set_visible(False)
        self.ax.xaxis.label.set_color('white')
        self.ax.yaxis.label.set_color('white')
        
        self.line_cpu, = self.ax.plot(self.x_data, self.cpu_data, label="CPU %", color="#ff5722")
        self.line_ram, = self.ax.plot(self.x_data, self.ram_data, label="RAM %", color="#03a9f4")
        self.line_disk, = self.ax.plot(self.x_data, self.disk_data, label="Disk %", color="#8bc34a")
        self.ax.set_ylim(0, 100)
        self.ax.set_xlim(0, 59)
        self.ax.legend(loc="upper left", facecolor='#2b2b2b', labelcolor='white')
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.monitor_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        
        self.metrics_labels_frame = ctk.CTkFrame(self.monitor_frame, corner_radius=10)
        self.metrics_labels_frame.pack(pady=(0, 10), padx=20, fill="x")
        
        self.metrics_labels_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)
        
        self.lbl_os = ctk.CTkLabel(self.metrics_labels_frame, text="OS: Unknown", text_color="#e0e0e0", font=ctk.CTkFont(size=14, weight="bold"))
        self.lbl_os.grid(row=0, column=0, pady=10)
        self.lbl_cpu = ctk.CTkLabel(self.metrics_labels_frame, text="CPU: 0%", text_color="#ff5722", font=ctk.CTkFont(size=14, weight="bold"))
        self.lbl_cpu.grid(row=0, column=1, pady=10)
        self.lbl_ram = ctk.CTkLabel(self.metrics_labels_frame, text="RAM: 0%", text_color="#03a9f4", font=ctk.CTkFont(size=14, weight="bold"))
        self.lbl_ram.grid(row=0, column=2, pady=10)
        self.lbl_disk = ctk.CTkLabel(self.metrics_labels_frame, text="Disk: 0%", text_color="#8bc34a", font=ctk.CTkFont(size=14, weight="bold"))
        self.lbl_disk.grid(row=0, column=3, pady=10)
        self.lbl_uptime = ctk.CTkLabel(self.metrics_labels_frame, text="Uptime: Unknown", text_color="#ffffff", font=ctk.CTkFont(size=14, weight="bold"))
        self.lbl_uptime.grid(row=0, column=4, pady=10)
        
        # teste de rede
        self.network_frame = ctk.CTkFrame(self.scroll_frame)
        self.network_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        self.network_title = ctk.CTkLabel(self.network_frame, text="Network & Connectivity", font=ctk.CTkFont(size=16, weight="bold"))
        self.network_title.pack(pady=10)
        self.btn_network = ctk.CTkButton(self.network_frame, text="Run Network Tools", command=self.run_network_tests_bg)
        self.btn_network.pack(pady=10)
        self.network_results = ctk.CTkTextbox(self.network_frame, height=250)
        self.network_results.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.audit_frame = ctk.CTkFrame(self.scroll_frame)
        self.audit_frame.grid(row=1, column=1, sticky="nsew", padx=10, pady=10)
        
        self.audit_title = ctk.CTkLabel(self.audit_frame, text="Security Audit", font=ctk.CTkFont(size=16, weight="bold"))
        self.audit_title.pack(pady=10)
        self.btn_audit = ctk.CTkButton(self.audit_frame, text="Run Basic Audit", command=self.run_audit_bg)
        self.btn_audit.pack(pady=10)
        
        self.btn_sync_time = ctk.CTkButton(
            self.audit_frame, text="Synchronize Time with Host", 
            command=self.sync_time_bg, fg_color="#ff9800", hover_color="#f57c00", text_color="black"
        )
        
        self.audit_results = ctk.CTkTextbox(self.audit_frame, height=250)
        self.audit_results.pack(fill="both", expand=True, padx=10, pady=10)

    def toggle_connection(self):
        if self.ssh.connected:
            self.ssh.disconnect()
            self.is_monitoring = False
            self.connect_btn.configure(text="Connect")
            self.status_label.configure(text="Disconnected", text_color="red")
        else:
            self.connect_btn.configure(state="disabled")
            self.status_label.configure(text="Connecting...", text_color="orange")
            threading.Thread(target=self.connect_bg).start()

    def connect_bg(self):
        ip = self.ip_entry.get()
        port = self.port_entry.get() or "22"
        user = self.user_entry.get()
        passwd = self.pass_entry.get()
        
        if not ip or not user:
            self.update_status("IP & User required", "red")
            self.connect_btn.configure(state="normal")
            return
            
        try:
            port = int(port)
        except ValueError:
            self.update_status("Invalid Port", "red")
            self.connect_btn.configure(state="normal")
            return
            
        success, msg = self.ssh.connect(ip, port, user, passwd)
        
        if success:
            self.after(0, lambda: self.update_status("Connected", "green"))
            self.after(0, lambda: self.connect_btn.configure(text="Disconnect", state="normal"))
            self.is_monitoring = True
            
            os_info = self.metrics.get_os_info()
            self.after(0, lambda name=os_info: self.lbl_os.configure(text=f"OS: {name}"))
            
            if self.update_tab_name_callback:
                self.after(0, lambda ip_addr=ip: self.update_tab_name_callback(ip_addr))
                
            threading.Thread(target=self.monitor_loop, daemon=True).start()
        else:
            self.after(0, lambda: self.update_status("Failed", "red"))
            self.after(0, lambda: self.connect_btn.configure(state="normal"))

    def update_status(self, text, color):
        self.status_label.configure(text=text, text_color=color)

    def run_network_tests_bg(self):
        if not self.ssh.connected:
            self.network_results.delete("0.0", "end")
            self.network_results.insert("end", "Not connected.\n")
            return
        self.btn_network.configure(state="disabled")
        self.network_results.delete("0.0", "end")
        self.network_results.insert("end", "Running tests... Please wait.\n")
        threading.Thread(target=self._run_network_tests).start()
        
    def _run_network_tests(self):
        results = self.metrics.run_network_tests()
        
        out = "--- Network Configuration ---\n"
        out += results.get("config", "Config analysis failed") + "\n\n"
        
        out += "--- Gateway Ping ---\n"
        out += f"Status: {results['gateway']['status']}\n"
        out += f"Loss: {results['gateway']['loss']}\n"
        out += f"RTT: {results['gateway']['rtt']}\n\n"
        
        out += "--- Internet Ping ---\n"
        out += f"Status: {results['internet']['status']}\n"
        out += f"Loss: {results['internet']['loss']}\n"
        out += f"RTT: {results['internet']['rtt']}\n"
        
        self.network_results.delete("0.0", "end")
        self.network_results.insert("end", out)
        self.btn_network.configure(state="normal")

    def run_audit_bg(self):
        if not self.ssh.connected:
            self.audit_results.delete("0.0", "end")
            self.audit_results.insert("end", "Not connected.\n")
            return
        self.btn_audit.configure(state="disabled")
        self.audit_results.delete("0.0", "end")
        self.audit_results.insert("end", "Running audit... Please wait.\n")
        threading.Thread(target=self._run_audit).start()

    def _run_audit(self):
        audit = self.metrics.run_security_audit()
        out = ""
        out += "--- Firewall ---\n"
        out += audit.get("firewall", "") + "\n\n"
        
        out += "--- Local Users ---\n"
        out += audit.get("users", "") + "\n\n"
        
        out += "--- System Time ---\n"
        out += audit.get("time", "") + "\n\n"
        
        out += "--- Top 3 Full Partitions ---\n"
        out += audit.get("disk", "") + "\n\n"
        
        out += "--- Log Management ---\n"
        out += audit.get("logs", "") + "\n\n"
        
        out += "--- Ports in Use (Top 5) ---\n"
        out += audit.get("ports", "") + "\n\n"
        
        out += "--- SSH Status ---\n"
        out += audit.get("ssh", "") + "\n"
        
        self.audit_results.delete("0.0", "end")
        self.audit_results.insert("end", out)
        self.btn_audit.configure(state="normal")
        
        self.btn_sync_time.pack(pady=5, before=self.audit_results)

    def sync_time_bg(self):
        # evita spam
        self.btn_sync_time.configure(state="disabled", text="Syncing...")
        threading.Thread(target=self._sync_time).start()
        
    def _sync_time(self):
        try:
            import datetime
            local_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            success, out = self.metrics.sync_time_with_local(local_time_str)
            
            self.audit_results.insert("end", f"\n--- Sync Time Result ---\nSent: {local_time_str}\nStatus: {'OK' if success else 'FAIL'}\nOutput: {out}\n")
            self.audit_results.see("end")
            
            if success:
                self.btn_sync_time.configure(text="Synchronized!", fg_color="#4caf50", hover_color="#388e3c")
            else:
                self.btn_sync_time.configure(state="normal", text="Failed! try again", fg_color="#f44336", text_color="white")
                
        except Exception as e:
            print("Failed time sync background process:", e)
            self.btn_sync_time.configure(state="normal", text="Synchronize Time with Host", fg_color="#ff9800", text_color="black")

    def monitor_loop(self):
        while self.is_monitoring and self.ssh.connected:
            cpu = self.metrics.get_cpu_usage()
            ram = self.metrics.get_ram_usage()
            disk = self.metrics.get_disk_usage()
            uptime = self.metrics.get_uptime()
            
            self.cpu_data.pop(0)
            self.cpu_data.append(cpu)
            
            self.ram_data.pop(0)
            self.ram_data.append(ram)
            
            self.disk_data.pop(0)
            self.disk_data.append(disk)
            
            try:
                self.after(0, self.update_chart, cpu, ram, disk, uptime)
            except:
                break
            
            time.sleep(2)
            
    def update_chart(self, cpu, ram, disk, uptime):
        self.lbl_cpu.configure(text=f"CPU: {cpu:.1f}%")
        self.lbl_ram.configure(text=f"RAM: {ram:.1f}%")
        self.lbl_disk.configure(text=f"Disk: {disk:.1f}%")
        self.lbl_uptime.configure(text=f"Uptime: {uptime}")
        
        self.line_cpu.set_data(self.x_data, self.cpu_data)
        self.line_ram.set_data(self.x_data, self.ram_data)
        self.line_disk.set_data(self.x_data, self.disk_data)
        self.canvas.draw_idle()


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Quick Audit Linux - Multi VM")
        self.geometry("1100x750")
        
        self.tab_count = 0
        self.setup_ui()
        
    def setup_ui(self):
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        self.top_frame = ctk.CTkFrame(self, height=50)
        self.top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))
        
        self.app_title = ctk.CTkLabel(self.top_frame, text="Quick Audit Linux - by @Caio_Fndo", font=ctk.CTkFont(size=20, weight="bold"))
        self.app_title.pack(side="left", padx=20, pady=10)
        
        self.btn_add_tab = ctk.CTkButton(self.top_frame, text="+ Add VM Tab", width=120, command=self.add_tab)
        self.btn_add_tab.pack(side="right", padx=10, pady=10)
        
        self.btn_close_tab = ctk.CTkButton(
            self.top_frame, text="✖ Close current VM", width=120, 
            fg_color="#d32f2f", hover_color="#b71c1c", command=self.close_current_tab
        )
        self.btn_close_tab.pack(side="right", padx=10, pady=10)
        
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.tabview._segmented_button.configure(height=40, font=ctk.CTkFont(size=14, weight="bold"))
        
        self.add_tab()
        
    def add_tab(self):
        self.tab_count += 1
        initial_name = f"VM {self.tab_count}"
        self.tabview.add(initial_name)
        
        try:
            btn = self.tabview._segmented_button._buttons_dict[initial_name]
            
            frame = self.tabview.tab(initial_name)
            
            def update_tab_name(new_ip):
                try:
                    btn.configure(text=f"VM {initial_name.split(' ')[1]} ({new_ip})")
                except Exception:
                    pass
                    
            dashboard = VMDashboard(frame, tab_name_update_callback=update_tab_name)
            dashboard.pack(fill="both", expand=True)
            self.tabview.set(initial_name)
            
        except Exception as e:
            print("Error adding tab tweaks", e)
            
    def close_current_tab(self):
        try:
            current = self.tabview.get()
            if current:
                self.tabview.delete(current)
        except Exception as e:
            print("Failed closing tab", e)

if __name__ == "__main__":
    app = App()
    app.mainloop()
