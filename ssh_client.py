import paramiko
import threading

class SSHClient:
    def __init__(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.connected = False
        self.lock = threading.Lock()

    def connect(self, host, port, username, password=None, key_filename=None):
        self.password = password
        try:
            self.client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                key_filename=key_filename,
                timeout=10,
                look_for_keys=False if password else True,
                allow_agent=False if password else True
            )
            self.connected = True
            return True, "Connected successfully"
        except paramiko.AuthenticationException:
            self.connected = False
            return False, "Authentication failed"
        except paramiko.SSHException as e:
            self.connected = False
            return False, f"SSH error: {str(e)}"
        except Exception as e:
            self.connected = False
            return False, f"Connection error: {str(e)}"

    def disconnect(self):
        if self.connected:
            self.client.close()
            self.connected = False

    def execute_command(self, command, timeout=10, use_sudo=False):
        if not self.connected:
            return False, "Not connected"
            
        ALLOWED_SUDO_COMMANDS = [
            "ufw status",
            "iptables -L -n",
            "ss -tulpan",
            "netstat -tulpn",
            "timedatectl set-ntp false",
            "timedatectl set-timezone",
            "date -s",
            "timedatectl set-ntp true"
        ]

        if use_sudo:
            is_allowed = False
            for allowed_cmd in ALLOWED_SUDO_COMMANDS:
                if command.startswith(allowed_cmd):
                    is_allowed = True
                    break
                    
            if not is_allowed:
                return False, f"Security Error: Command '{command}' is not authorized for sudo execution."

        try:
            with self.lock:
                if use_sudo and getattr(self, 'password', None):
                    command = f"sudo -S {command}"
                
                stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
                
                if use_sudo and getattr(self, 'password', None):
                    stdin.write(self.password + '\n')
                    stdin.flush()
                out = stdout.read().decode('utf-8').strip()
                err = stderr.read().decode('utf-8').strip()
                exit_status = stdout.channel.recv_exit_status()
                if exit_status == 0:
                    return True, out
                else:
                    return False, err if err else out
        except Exception as e:
            return False, f"Execution error: {str(e)}"
