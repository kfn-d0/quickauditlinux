import re

class MetricsCollector:
    def __init__(self, ssh_client):
        self.ssh = ssh_client
        self.last_cpu_stat = None

    def get_cpu_usage(self):
        success, output = self.ssh.execute_command("grep '^cpu ' /proc/stat")
        if success and output:
            parts = output.split()
            if len(parts) >= 5:
                try:
                    user = float(parts[1])
                    nice = float(parts[2])
                    system = float(parts[3])
                    idle = float(parts[4])
                    iowait = float(parts[5]) if len(parts) > 5 else 0.0
                    irq = float(parts[6]) if len(parts) > 6 else 0.0
                    softirq = float(parts[7]) if len(parts) > 7 else 0.0
                    steal = float(parts[8]) if len(parts) > 8 else 0.0

                    idle_time = idle + iowait
                    non_idle_time = user + nice + system + irq + softirq + steal
                    total_time = idle_time + non_idle_time

                    if self.last_cpu_stat:
                        prev_total, prev_idle = self.last_cpu_stat
                        total_diff = total_time - prev_total
                        idle_diff = idle_time - prev_idle

                        if total_diff > 0:
                            usage = (total_diff - idle_diff) / total_diff * 100.0
                        else:
                            usage = 0.0
                    else:
                        usage = 0.0

                    self.last_cpu_stat = (total_time, idle_time)
                    return usage
                except Exception:
                    pass
        return 0.0

    def get_ram_usage(self):
        success, output = self.ssh.execute_command("free -m | awk 'NR==2{print $3*100/$2 }'")
        if success:
            try:
                return float(output.replace(',', '.'))
            except ValueError:
                pass
        return 0.0

    def get_disk_usage(self):
        success, output = self.ssh.execute_command("df -h / | awk 'NR==2{print $5}' | sed 's/%//'")
        if success:
            try:
                return float(output.replace(',', '.'))
            except ValueError:
                pass
        return 0.0

    def get_os_info(self):
        success, output = self.ssh.execute_command("cat /etc/os-release | grep '^PRETTY_NAME=' | cut -d'=' -f2 | tr -d '\"'")
        if success and output:
            return output.strip()
            
        success, output = self.ssh.execute_command("cat /etc/*release | head -n 1")
        if success and output:
            return output.strip()
            
        success, output = self.ssh.execute_command("uname -snrv")
        if success and output:
            return output.strip()
            
        return "Unknown OS"

    def get_uptime(self):
        success, output = self.ssh.execute_command("uptime -p")
        if success and output.startswith("up "):
            return output[3:]
        
        success, output = self.ssh.execute_command("cat /proc/uptime | awk '{print $1}'")
        if success:
            try:
                seconds = float(output)
                mins = int(seconds / 60) % 60
                hours = int(seconds / 3600) % 24
                days = int(seconds / 86400)
                res = []
                if days > 0: res.append(f"{days} days")
                if hours > 0: res.append(f"{hours} hours")
                if mins > 0: res.append(f"{mins} minutes")
                return ", ".join(res) if res else "Less than a minute"
            except:
                pass
        return "Unknown"

    def get_network_config(self):
        config = ""
        succ, out = self.ssh.execute_command("ip route | grep default | awk '{print $5}' | head -n 1")
        ifce = out.strip() if succ and out else "eth0"
        
        succ, out = self.ssh.execute_command(f"ip -4 addr show {ifce} | grep -o 'inet [0-9./]*' | awk '{{print $2}}'")
        ip_addr = out.strip() if succ and out else "Unknown"
        
        succ, out = self.ssh.execute_command(f"ip route | grep default | grep {ifce}")
        route_out = out.lower() if succ else ""
        
        method = "Unknown"
        if "dhcp" in route_out:
            method = "DHCP (identified via routing table)"
        else:
            succ_nm, nm_out = self.ssh.execute_command(f"nmcli -t -f ipv4.method dev show {ifce} 2>/dev/null", timeout=2)
            if succ_nm and nm_out:
                if "auto" in nm_out.lower():
                    method = "DHCP (via NetworkManager)"
                elif "manual" in nm_out.lower():
                    method = "Static (via NetworkManager)"
                else:
                    method = nm_out.strip()
            else:
                method = "Likely Static (No DHCP detected in route or NM)"
                
        succ_dns, dns_out = self.ssh.execute_command("grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | paste -sd ', ' -")
        dns_servers = dns_out.strip() if succ_dns and dns_out else "Not Found"
                
        config += f"Interface: {ifce}\n"
        config += f"IP Address: {ip_addr}\n"
        config += f"Allocation: {method}\n"
        config += f"DNS Servers: {dns_servers}\n"
        
        return config

    def run_network_tests(self):
        net_cfg = self.get_network_config()

        success, gw_out = self.ssh.execute_command("ip route | grep default | awk '{print $3}'")
        gw_status = {"loss": "N/A", "rtt": "N/A", "status": "FAIL"}
        
        if success and gw_out:
            gw_ip = gw_out.strip()
            succ_ping, ping_out = self.ssh.execute_command(f"ping -c 3 -W 2 {gw_ip}")
            if succ_ping or ping_out:
                loss_match = re.search(r'(\d+)% packet loss', ping_out)
                rtt_match = re.search(r'min/avg/max/mdev = [\d\.]+/([\d\.]+)/[\d\.]+/', ping_out)
                if loss_match:
                    gw_status["loss"] = loss_match.group(1) + "%"
                if rtt_match:
                    gw_status["rtt"] = rtt_match.group(1) + " ms"
                if "0% packet loss" in ping_out:
                    gw_status["status"] = "OK"
                elif loss_match and int(loss_match.group(1)) > 0:
                    gw_status["status"] = "WARNING/FAIL"
                else:
                    gw_status["status"] = "OK"

        # ping para 8.8.8.8
        inet_status = {"loss": "N/A", "rtt": "N/A", "status": "FAIL"}
        succ_ping, ping_out = self.ssh.execute_command("ping -c 3 -W 2 8.8.8.8")
        if succ_ping or ping_out:
            loss_match = re.search(r'(\d+)% packet loss', ping_out)
            rtt_match = re.search(r'min/avg/max/mdev = [\d\.]+/([\d\.]+)/[\d\.]+/', ping_out)
            if loss_match:
                inet_status["loss"] = loss_match.group(1) + "%"
            if rtt_match:
                inet_status["rtt"] = rtt_match.group(1) + " ms"
            if "0% packet loss" in ping_out:
                inet_status["status"] = "OK"
            elif loss_match and int(loss_match.group(1)) > 0:
                inet_status["status"] = "WARNING/FAIL"
            else:
                inet_status["status"] = "OK"

        return {"gateway": gw_status, "internet": inet_status, "config": net_cfg}

    def run_security_audit(self):
        audit = {}
        succ, out = self.ssh.execute_command("ufw status", use_sudo=True)
        if not succ and ("command not found" in out.lower() or "not found" in out.lower()):
            succ, out = self.ssh.execute_command("iptables -L -n | head -n 5", use_sudo=True)
            audit["firewall"] = "iptables output:\n" + out if succ else "Failed to get firewall status"
        else:
            audit["firewall"] = out if succ else f"Failed: {out} (Might need sudo password)"

        succ, out = self.ssh.execute_command("cat /etc/passwd | awk -F':' '$3 >= 1000 && $3 != 65534 {print $1}'")
        audit["users"] = out if succ else "Failed: " + out

        succ, out = self.ssh.execute_command("timedatectl | grep -E 'Local time|Time zone|NTP service'")
        if succ and "Local time" not in out:
            succ2, out2 = self.ssh.execute_command("date")
            out = f"Local time: {out2}\n{out}"
        audit["time"] = out if succ else "Failed: " + out

        succ, out = self.ssh.execute_command("systemctl is-active ssh || systemctl is-active sshd")
        if out.strip() == "":
            succ, out = self.ssh.execute_command("service ssh status || service sshd status")
        audit["ssh"] = "Active" if "active" in out.lower() or "running" in out.lower() else out
        
        succ, out = self.ssh.execute_command("df -hP | grep -vE '^Filesystem|tmpfs|cdrom' | sort -rn -k 5 | head -n 3 | awk '{print $5, $1, $6}'")
        if succ and out:
            audit["disk"] = "\n".join([f"{line.split()[0]} Full -> {line.split()[1]} (Mount: {line.split()[2]})" if len(line.split())==3 else line for line in out.split('\n')])
        else:
            audit["disk"] = "Failed to analyze partitions"
            
        log_report = ""
        succ, out = self.ssh.execute_command("du -ah /var/log 2>/dev/null | sort -rh | head -n 3")
        if succ and out:
            log_report += "Maiores logs no /var/log:\n" + out + "\n"
        
        succ, out = self.ssh.execute_command("systemctl is-active logrotate.timer || service logrotate status")
        log_report += f"Logrotate service: {'Active (Timer)' if 'active' in out.lower() else 'Inactive/Missing'}"
        audit["logs"] = log_report
        
        succ, out = self.ssh.execute_command("ss -tulpan | grep LISTEN | awk '{print $5, $7}'", use_sudo=True)
        if not succ or not out: 
            succ, out = self.ssh.execute_command("netstat -tulpn | grep LISTEN | awk '{print $4, $7}'", use_sudo=True)
        
        if succ and out:
            formatted_ports = []
            seen_ports = set()
            for line in out.strip().split('\n'):
                parts = line.split(maxsplit=1)
                if len(parts) >= 2:
                    ip_port = parts[0]
                    process_info = parts[1]
                    
                    if ':' in ip_port:
                        port = ip_port.split(':')[-1]
                    else:
                        port = ip_port
                        
                    if '("' in process_info:
                        proc_name = process_info.split('("')[1].split('"')[0]
                    elif '/' in process_info:
                        proc_name = process_info.split('/')[-1]
                    else:
                        proc_name = process_info
                    
                    if port not in seen_ports:
                        formatted_ports.append(f"Port: {port} - PID/Processo: {proc_name}")
                        seen_ports.add(port)
                        
                    if len(seen_ports) >= 5: 
                        break
                        
            audit["ports"] = "\n".join(formatted_ports) if formatted_ports else "No listening ports found."
        else:
            audit["ports"] = "Failed to read open ports (Sudo needed or ss/netstat not installed)"

        return audit
    def sync_time_with_local(self, local_time_str, is_brazil=True):
        self.ssh.execute_command("timedatectl set-ntp false", use_sudo=True)
        
        if is_brazil:
            self.ssh.execute_command("timedatectl set-timezone America/Sao_Paulo", use_sudo=True)
            
        success, out = self.ssh.execute_command(f'date -s "{local_time_str}"', use_sudo=True)
        
        self.ssh.execute_command("timedatectl set-ntp true", use_sudo=True)
        
        return success, out
