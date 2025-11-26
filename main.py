import socket
import threading
import time
import random
import os
import json

class server():
    def __init__(self, config_path='./config/config.json'):
        # 读取配置文件并创建警告目录
        if not os.path.exists('./warn/'):
            os.mkdir('./warn/')
        config = json.load(open(config_path, 'r'))
        self.log_path = config['log_path']
        self.counter = 0
        self.scan_counter = {} #ip:count
        self.blacklist = config['blacklist']
        self.prevent_scan_frequency = config['prevent_scan_frequency']
        self.init_dict_path = config['init_dict_path']
        self.web = config['web'] if 'web' in config else False
        self.port_forwarding = config['port_forwarding'] if 'port_forwarding' in config else {}
        self.log_lock = threading.Lock()
        if "check_dict" in config:
            self.check_dict = config['check_dict']
        else:
            self.check_dict = ['./db/all.txt']

    def get_time(self):
        # 获得格式化时间
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    
    def start(self):
        if self.web:
            threading.Thread(target=self.run_waf_web).start()
            self.log(f"[{self.get_time()}] [INFO] HTTP Web Management Interface started.")
        for line in self.port_forwarding:
            try:
                threading.Thread(target=self.__start, args=(int(line[1]), int(line[0]),)).start()
            except OSError as e:
                self.log(f"[{self.get_time()}] [ERROR] Failed to start server on port {line[0]}: {e}")

    def run_waf_web(self):
        os.system("cd http_app && http_server.py")

    def __start(self, local_port, port=None, host="0.0.0.0"):
        if not port:
            return 
        # 启动服务器并监听连接
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                s.listen()
            except OSError as e:
                self.log(f"[{self.get_time()}] [ERROR] Failed to bind to {host}:{port}: {e}")
                return
            self.log(f'[{self.get_time()}] [INFO] WAF Server started on {host}:{port}, forwarding to local port {local_port}')
            while True:
                conn, addr = s.accept()
                self.counter += 1
                threading.Thread(target=self.handle_request, args=(conn,addr, local_port)).start()

    def log(self, message):
        self.log_lock.acquire()
        # 记录日志到控制台和文件
        print(message)
        if self.log_path:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(message + '\n')
                f.close()
        if 'ATTACK' in message:
            try:
                with open('./warn/attack_log.txt', 'a', encoding='utf-8') as f:
                    f.write(message + '\n')
            except Exception as e:
                self.log(f"[{self.get_time()}] [ERROR] Failed to write to attack log: {e}")
            finally:
                self.log_lock.release()
        self.log_lock.release()

    def prevent_scan(self, data, addr): 
        # 使用dirsearch字典进行扫描防护检查
        if not self.waf_check(data, check_data='./db/dirsearch.txt', addr=addr)[0]:
            data = data.replace("\n", "     ")
            self.log(f"[{self.get_time()}] [!ATTACK] {addr} Scan pattern detected: {data}    Scan App: dirsearch")
            return False
        if not self.waf_check(data, check_data='./db/dirb.txt', addr=addr)[0]:
            data = data.replace("\n", "     ")
            self.log(f"[{self.get_time()}] [!ATTACK] {addr} Scan pattern detected: {data}    Scan App: dirb")
            return False
        return True

    def waf_check(self, data, addr, check_data=None, token=None):

        # 将数据转换为小写以进行不区分大小写的匹配
        data = data.lower()

        # 默认使用初始化字典
        if not check_data:
            check_data = self.init_dict_path

        # 创建会话token    
        if not token:
            token = self.create_token(addr)

        # 读取检查字典并进行匹配    
        with open(check_data, 'r') as f:
            patterns = f.readlines()

        # 逐行检查数据    
        for pattern in patterns:
            pattern = pattern.strip()
            # 如果匹配到恶意模式，记录日志并保存警告文件
            if pattern and pattern in data:
                self.log(f'[{self.get_time()}] [WARN] {token} Malicious pattern detected: {pattern}')
                with open(f'./warn/{token}.txt', 'w') as warn_file:
                    warn_file.write(f"<Time>: {self.get_time()}\n")
                    warn_file.write(f"<Address>: {addr}\n")
                    warn_file.write(f"<Pattern>: {pattern}\n")
                    warn_file.write(f"<Data>: \n{'='*30}\n\n{data}\n\n{'='*30}\n")
                    warn_file.write(f"<Token>: {token}\n")
                    warn_file.close()
                return False, None
        return True, token
    
    def create_token(self, addr):
        # 生成唯一token
        return f"{hex(int(time.time()) * int(addr[0].split('.')[0]) * self.counter * addr[1])[2:]}-{hex(random.randint(100000000, 999999999))[2:]}-{hex(int(time.time()))}"

    def handle_request(self, conn, addr, local_port):
        # 前置黑名单检查
        if addr[0] in self.blacklist:
            self.log(f'[{self.get_time()}] [BLOCKED] Connection attempt from blacklisted IP {addr}')
            ret = b"HTTP/1.1 403 Forbidden\r\n\r\nForbidden  Your IP has been blacklisted.\r\n"
            conn.sendall(ret)
            conn.close()  # 确保连接关闭
            return
        
        self.log(f'[{self.get_time()}] [INFO] Connection from {addr}')
        
        try:
            data = conn.recv(1024 ** 2).decode('utf-8')

            if addr[0] not in self.scan_counter:
                self.scan_counter[addr[0]] = 0

            # 解析HTTP请求头, 并添加参数检查
            if "GET" in data:
                data = data.split('\r\n')[0]
            elif "POST" in data:
                data = data.split('\r\n')[0] + "\n" + data.split('\r\n')[-1]

            # 再次检查黑名单（防止在接收数据期间IP被加入黑名单）
            if addr[0] in self.blacklist:
                self.log(f'[{self.get_time()}] [BLOCKED] Request from blacklisted IP {addr} during processing')
                ret = b"HTTP/1.1 403 Forbidden\r\n\r\nForbidden  Your IP has been blacklisted.\r\n"
                conn.sendall(ret)
                return
            
            # WAF检查
            token = None
            for dict_path in self.check_dict:
                bool_, token = self.waf_check(data, addr=addr, check_data=dict_path, token=token)
                if not bool_:
                    socket_response = f"HTTP/1.1 403 Forbidden\r\n\r\nForbidden  Your request has been blocked by WAF.  time {self.get_time()}"
                    conn.sendall(socket_response.encode('utf-8'))
                    return
            
            # 扫描防护检查
            if not self.prevent_scan(data, addr):
                self.log(f'[{self.get_time()}] [INFO] Scan attempt from {addr} blocked.')
                if addr[0] not in self.scan_counter:
                    self.scan_counter[addr[0]] = 1
                else:
                    self.scan_counter[addr[0]] += 1
                
                self.log(f'[{self.get_time()}] [INFO] {addr[0]} scan count: {self.scan_counter[addr[0]]}')
                
                # 检查是否达到阈值并加入黑名单
            if self.scan_counter[addr[0]] > self.prevent_scan_frequency and addr[0] not in self.blacklist:
                self.blacklist.append(addr[0])
                self.log(f'[{self.get_time()}] [!ATTACK] {addr[0]} added to blacklist.')
                # 立即返回，不处理后续请求
                ret = b"HTTP/1.1 403 Forbidden\r\n\r\nForbidden  Your IP has been blacklisted due to suspicious activity.\r\n"
                conn.sendall(ret)
                return
            
            # 只有通过所有检查的请求才转发到后端
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", local_port))
            s.sendall(data.encode('utf-8'))
            response = s.recv(1024 ** 2)
            conn.sendall(response)
            
        
        # 捕获所有异常，防止服务器崩溃
        except Exception as e:
            self.log(f'[{self.get_time()}] [ERROR] Handling request from {addr}: {e}')
        finally:
            conn.close()

if __name__ == "__main__":
    # 开启服务器
    server_instance = server()
    server_instance.start()