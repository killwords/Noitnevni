import socket
import threading
import time
import urllib.parse
import cgi
import os
import glob
import json
import traceback
import platform

# Optional: psutil for accurate CPU/memory stats. If not installed, fallback to N/A
try:
    import psutil
    _HAS_PSUTIL = True
except Exception:
    _HAS_PSUTIL = False

class Server:
    def __init__(self):
        setting = open("./server.ini", "r").read().split("\n")
        for s in setting:
            if "=" in s:
                key, value = s.split("=")
                key = key.strip()
                if key == "log_path":
                    self.path = value.strip()
                elif key == "port":
                    self.port = int(value.strip())
                elif key == "host":
                    self.host = value.strip()
                elif key == "shell":
                    self.shell = value.strip()
                elif key == "index_file":
                    self.index_file = value.strip()
                elif key == "base_path":
                    self.base_path = value.strip()
        self.ERROR_PAGE = """
        <html>
        <head>
            <title>%code%</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    font-size: 16px;
                    line-height: 1.5;
                    margin: 0;
                    padding: 0;
                }
                h1 {
                    font-size: 32px;
                    margin: 0 0 20px 0;
                }
                p {
                    margin: 0 0 10px 0;
                }
            </style>
        </head>
        <body>
            <h1>%code%</h1>
            <p>%message%</p>
        </body>
        </html>
        """
        # 运行时采样数据（每5秒采样一次），只在面板使用，不影响WAF
        self.metrics_lock = threading.Lock()
        self.metrics = []  # 每项: {'ts': ..., 'cpu':..., 'memory':..., 'disk_percent':..., 'net_sent_bps':..., 'net_recv_bps':...}
        self._prev_net = None
        self._prev_disk_io = None
        # 启动采样线程
        threading.Thread(target=self._metrics_collector, daemon=True).start()

    def parse_query_string(self, query_string):
        """解析查询字符串为字典"""
        params = {}
        if query_string:
            pairs = query_string.split('&')
            for pair in pairs:
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    params[urllib.parse.unquote(key)] = urllib.parse.unquote(value)
        return params

    def parse_post_data(self, headers, body):
        """解析POST数据"""
        content_type = ""
        for header in headers:
            if header.lower().startswith('content-type:'):
                content_type = header.split(':', 1)[1].strip()
                break
        
        if 'application/x-www-form-urlencoded' in content_type:
            return self.parse_query_string(body)
        elif 'multipart/form-data' in content_type:
            # 简化处理，实际应该使用cgi模块完整解析
            return {}
        return {}

    def execute_python_code(self, code, variables):
        """在安全的环境中执行Python代码（支持多行）"""
        try:
            # 创建安全的执行环境 - 移除危险函数
            safe_builtins = {
                'str': str, 'int': int, 'float': float, 'bool': bool,
                'len': len, 'range': range, 'list': list, 'dict': dict,
                'tuple': tuple, 'set': set, 'min': min, 'max': max,
                'sum': sum, 'abs': abs, 'round': round,
                'print': print,
                'enumerate': enumerate, 'zip': zip, 'filter': filter, 'map': map
            }
            
            local_vars = variables.copy()
            local_vars['__builtins__'] = safe_builtins
            local_vars['time'] = time
            
            # 检查代码是否包含危险操作
            dangerous_keywords = []
            for keyword in dangerous_keywords:
                if keyword in code:
                    return f"安全错误: 检测到危险操作 '{keyword}'"
            
            # 检查代码是表达式还是语句
            code = code.strip()
            
            # 如果是多行代码或者是复杂的语句
            if '\n' in code or ';' in code or ':' in code or '=' in code or code.startswith('print'):
                # 使用exec执行多行代码
                exec_globals = {}
                exec_locals = local_vars.copy()
                
                # 重定向print输出
                import io
                output = io.StringIO()
                exec_locals['print'] = lambda *args, **kwargs: print(*args, file=output, **kwargs)
                
                try:
                    # 首先尝试编译代码
                    compiled_code = compile(code, '<string>', 'exec')
                    exec(compiled_code, exec_globals, exec_locals)
                    
                    # 获取输出
                    result = output.getvalue()
                    
                    # 如果没有输出，尝试获取最后一个表达式的结果
                    if not result:
                        # 如果是赋值语句，尝试获取变量值
                        lines = code.strip().split('\n')
                        last_line = lines[-1].strip()
                        if '=' not in last_line and not last_line.startswith('print'):
                            try:
                                # 尝试将最后一行作为表达式执行
                                compiled_expr = compile(last_line, '<string>', 'eval')
                                result = str(eval(compiled_expr, exec_globals, exec_locals))
                            except:
                                # 如果最后一行不是表达式，返回空字符串
                                result = ""
                    
                    return result if result else ""
                    
                except Exception as e:
                    return f"执行错误: {str(e)}"
            else:
                # 单行表达式，使用eval
                try:
                    compiled_code = compile(code, '<string>', 'eval')
                    result = eval(compiled_code, local_vars)
                    return str(result)
                except:
                    # 如果eval失败，尝试用exec
                    try:
                        exec_globals = {}
                        exec_locals = local_vars.copy()
                        import io
                        output = io.StringIO()
                        exec_locals['print'] = lambda *args, **kwargs: print(*args, file=output, **kwargs)
                        
                        compiled_code = compile(code, '<string>', 'exec')
                        exec(compiled_code, exec_globals, exec_locals)
                        result = output.getvalue()
                        return result if result else ""
                    except Exception as e:
                        return f"执行错误: {str(e)}"
                        
        except Exception as e:
            return f"错误: {str(e)}"

    def process_html_template(self, html_content, get_params=None, post_params=None):
        """处理HTML模板，执行<pyyp>标签和替换$变量"""
        if get_params is None:
            get_params = {}
        if post_params is None:
            post_params = {}
            
        # 创建变量环境
        variables = {
            '_GET': get_params,  # 改为合法的Python变量名
            '_POST': post_params,  # 改为合法的Python变量名
            'age': get_params.get('age') or post_params.get('age'),
            'time': time
        }
        
        # 首先替换HTML中的$变量
        for var_name, var_value in variables.items():
            if isinstance(var_value, dict):
                # 处理_GET和_POST字典
                for key, value in var_value.items():
                    placeholder = f"${key}"
                    if placeholder in html_content:
                        html_content = html_content.replace(placeholder, f"'{str(value)}'")  # 加上引号
            else:
                placeholder = f"${var_name}"
                if placeholder in html_content:
                    html_content = html_content.replace(placeholder, f"'{str(var_value)}'")  # 加上引号
        
        # 替换直接的$age引用
        if '$age' in html_content:
            age_value = variables.get('age', '')
            html_content = html_content.replace('$age', f"'{str(age_value)}'")
        
        # 处理<pyyp>标签 - 支持多行代码
        start_tag = "<pyyp>"
        end_tag = "</pyyp>"
        
        while start_tag in html_content:
            start_index = html_content.find(start_tag)
            if start_index == -1:
                break
                
            end_index = html_content.find(end_tag, start_index)
            if end_index == -1:
                break
                
            # 提取代码内容
            code_start = start_index + len(start_tag)
            code_content = html_content[code_start:end_index].strip()
            
            # 在代码执行前替换变量引用
            code_content = self.replace_variables_in_code(code_content, variables)
            
            # 执行Python代码
            result = self.execute_python_code(code_content, variables)
            
            # 替换代码块为执行结果
            html_content = html_content[:start_index] + result + html_content[end_index + len(end_tag):]
            
        return html_content

    # --- 管理面板辅助方法 ---
    def _safe_db_path(self, name):
        # 只允许 db 目录下的文件名（防止路径遍历）
        if not name or '/' in name or '\\' in name or '..' in name:
            raise ValueError('Invalid filename')
        return os.path.normpath(os.path.join('..', 'db', name))

    def _config_path(self):
        return os.path.normpath(os.path.join('..', 'config', 'config.json'))

    def api_list_dicts(self):
        files = []
        for p in glob.glob(os.path.join('..', 'db', '*.txt')):
            files.append(os.path.basename(p))
        return {'ok': True, 'files': files}

    def api_get_dict(self, name):
        try:
            path = self._safe_db_path(name)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            return {'ok': True, 'name': name, 'content': content}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def api_save_dict(self, name, content):
        try:
            path = self._safe_db_path(name)
            # 强制保存为小写
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content.lower())
            return {'ok': True, 'name': name}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def api_get_config(self):
        try:
            path = self._config_path()
            with open(path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            return {'ok': True, 'config': cfg}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def api_save_config(self, cfg_obj):
        try:
            path = self._config_path()
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(cfg_obj, f, indent=2, ensure_ascii=False)
            return {'ok': True}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def api_status(self):
        status = {}
        try:
            if _HAS_PSUTIL:
                status['cpu_percent'] = psutil.cpu_percent(interval=0.1)
                status['memory_percent'] = psutil.virtual_memory().percent
            else:
                status['cpu_percent'] = 'N/A'
                status['memory_percent'] = 'N/A'

            # waf status: try read config.json and connect to local backend
            cfg_path = self._config_path()
            try:
                with open(cfg_path, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)

                # 首先尝试传统字段 local_ip/local_port
                waf_ip = cfg.get('local_ip')
                waf_port = None
                if cfg.get('local_port') is not None:
                    try:
                        waf_port = int(cfg.get('local_port'))
                    except Exception:
                        waf_port = None

                # 如果没有local_ip/local_port，尝试从 port_forwarding 推断（取第一个映射的目标local_port）
                if not waf_ip or not waf_port:
                    pf = cfg.get('port_forwarding')
                    if isinstance(pf, list) and len(pf) > 0:
                        first = pf[0]
                        # 支持两种格式: ["80","8080"] 或者 [["80","8080"],...]
                        if isinstance(first, list) and len(first) >= 2:
                            try:
                                waf_ip = waf_ip or '127.0.0.1'
                                waf_port = int(first[0])
                            except Exception:
                                waf_port = None
                print(waf_ip, waf_port)
                if waf_ip and waf_port:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(1)
                        s.connect((waf_ip, waf_port))
                        s.close()
                        status['waf_reachable'] = True
                    except Exception:
                        status['waf_reachable'] = False
                else:
                    status['waf_reachable'] = 'unknown'
            except Exception:
                status['waf_reachable'] = 'unknown'

            # website status: check index file exists
            try:
                idx_path = os.path.join(self.base_path, self.index_file)
                status['index_exists'] = os.path.exists(idx_path)
            except Exception:
                status['index_exists'] = False

            status['platform'] = platform.platform()
            return {'ok': True, 'status': status}
        except Exception as e:
            return {'ok': False, 'error': str(e), 'trace': traceback.format_exc()}

    def api_metrics(self):
        try:
            with self.metrics_lock:
                # return a copy to avoid race
                data = list(self.metrics)
            return {'ok': True, 'metrics': data}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def _metrics_collector(self):
        # collect metrics every 5 seconds
        interval = 5.0
        while True:
            try:
                ts = int(time.time())
                if _HAS_PSUTIL:
                    cpu = psutil.cpu_percent(interval=None)
                    memory = psutil.virtual_memory().percent
                    try:
                        # try to get disk for base_path
                        target_path = getattr(self, 'base_path', '/') or '/'
                        disk_percent = psutil.disk_usage(target_path).percent
                    except Exception:
                        try:
                            disk_percent = psutil.disk_usage('/').percent
                        except Exception:
                            disk_percent = None

                    net = psutil.net_io_counters()
                    disk_io = psutil.disk_io_counters()

                    if self._prev_net is not None:
                        sent_bps = max(0.0, (net.bytes_sent - self._prev_net.bytes_sent) / interval)
                        recv_bps = max(0.0, (net.bytes_recv - self._prev_net.bytes_recv) / interval)
                    else:
                        sent_bps = 0.0
                        recv_bps = 0.0

                    if self._prev_disk_io is not None:
                        disk_write_bps = max(0.0, (disk_io.write_bytes - self._prev_disk_io.write_bytes) / interval)
                        disk_read_bps = max(0.0, (disk_io.read_bytes - self._prev_disk_io.read_bytes) / interval)
                    else:
                        disk_write_bps = 0.0
                        disk_read_bps = 0.0

                    self._prev_net = net
                    self._prev_disk_io = disk_io
                else:
                    cpu = 'N/A'
                    memory = 'N/A'
                    disk_percent = 'N/A'
                    sent_bps = 'N/A'
                    recv_bps = 'N/A'
                    disk_write_bps = 'N/A'
                    disk_read_bps = 'N/A'

                item = {
                    'ts': ts,
                    'cpu': cpu,
                    'memory': memory,
                    'disk_percent': disk_percent,
                    'net_sent_bps': sent_bps,
                    'net_recv_bps': recv_bps,
                    'disk_write_bps': disk_write_bps,
                    'disk_read_bps': disk_read_bps
                }

                with self.metrics_lock:
                    self.metrics.append(item)
                    # keep last 360 samples (~30 minutes at 5s)
                    if len(self.metrics) > 360:
                        self.metrics = self.metrics[-360:]
            except Exception:
                # ignore sampling errors to avoid crashing
                pass
            time.sleep(interval)

    def replace_variables_in_code(self, code, variables):
        """在代码中替换变量引用"""
        # 替换 $_GET['key'] 为 _GET.get('key')
        import re
        code = re.sub(r'\$_GET\[\s*[\'"]([^\'"]+)[\'"]\s*\]', r"_GET.get('\1')", code)
        code = re.sub(r'\$_POST\[\s*[\'"]([^\'"]+)[\'"]\s*\]', r"_POST.get('\1')", code)
        
        # 替换 $_GET["key"] 为 _GET.get('key')
        code = re.sub(r'\$_GET\[\s*"([^"]+)"\s*\]', r"_GET.get('\1')", code)
        code = re.sub(r'\$_POST\[\s*"([^"]+)"\s*\]', r"_POST.get('\1')", code)
        
        # 替换 $变量名 为 '变量值'
        for var_name, var_value in variables.items():
            if var_name.startswith('_'):
                continue  # 跳过_GET和_POST
            placeholder = f"${var_name}"
            if placeholder in code:
                code = code.replace(placeholder, f"'{str(var_value)}'")
        
        return code

    def get_receive_data(self, code, data, message="OK"):
        """生成正确的HTTP响应格式"""
        # 根据状态码设置正确的状态描述
        status_messages = {
            200: "OK",
            400: "Bad Request",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error"
        }
        status_message = status_messages.get(code, message)
        
        # 计算内容长度
        content_length = len(data.encode('utf-8'))
        
        # 构建完整的HTTP响应
        response = f"HTTP/1.1 {code} {status_message}\r\n"
        response += "Server: Python/HTTP Server\r\n"
        response += "Content-Type: text/html; charset=UTF-8\r\n"
        response += f"Content-Length: {content_length}\r\n"
        response += f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += data
        
        return response

    def responese(self, request, addr):
        try:
            lines = request.split("\r\n")
            method = ""
            path = ""
            query_string = ""
            post_data = ""
            headers = []
            body = ""
            
            # 解析请求
            if lines:
                first_line = lines[0].split()
                if len(first_line) >= 2:
                    method = first_line[0]
                    full_path = first_line[1]
                    
                    # 分离路径和查询字符串
                    if '?' in full_path:
                        path, query_string = full_path.split('?', 1)
                    else:
                        path = full_path
                        query_string = ""
            
            # 分离头部和主体
            empty_line_index = -1
            for i, line in enumerate(lines):
                if line == "":
                    empty_line_index = i
                    break
                headers.append(line)
            
            if empty_line_index != -1 and empty_line_index + 1 < len(lines):
                body = "\r\n".join(lines[empty_line_index + 1:])
            
            get_params = self.parse_query_string(query_string)
            post_params = self.parse_post_data(headers, body) if method == "POST" else {}

            # 如果是 application/json 的 POST，尝试解析 body 为 JSON（前端会发送 JSON）
            headers_join = "\n".join(headers).lower()
            if method == 'POST' and 'application/json' in headers_join and body:
                try:
                    post_json = json.loads(body)
                    if isinstance(post_json, dict):
                        post_params = post_json
                except Exception:
                    # ignore json parse errors, 保留原 post_params
                    pass

            # 管理面板 API 路由：/admin 页面与 /api/*
            if path == '/admin':
                try:
                    with open(os.path.join(self.base_path, 'admin.html'), 'r', encoding='utf-8') as f:
                        data = f.read()
                    return self.get_receive_data(200, data)
                except Exception:
                    return self.get_receive_data(404, self.ERROR_PAGE.replace("%code%", "404").replace("%message%", "Admin page not found"))

            if path.startswith('/api/'):
                api_action = path[len('/api/'):]
                # GET endpoints
                if method == 'GET':
                    if api_action == 'status':
                        res = self.api_status()
                        return self.get_receive_data(200, json.dumps(res, ensure_ascii=False))
                    if api_action == 'list_dicts':
                        res = self.api_list_dicts()
                        return self.get_receive_data(200, json.dumps(res, ensure_ascii=False))
                    if api_action == 'get_dict':
                        name = get_params.get('name')
                        res = self.api_get_dict(name)
                        return self.get_receive_data(200, json.dumps(res, ensure_ascii=False))
                    if api_action == 'get_config':
                        res = self.api_get_config()
                        return self.get_receive_data(200, json.dumps(res, ensure_ascii=False))
                        if api_action == 'metrics':
                            res = self.api_metrics()
                            return self.get_receive_data(200, json.dumps(res, ensure_ascii=False))
                # POST endpoints
                if method == 'POST':
                    if api_action == 'save_dict':
                        name = post_params.get('name') if isinstance(post_params, dict) else None
                        content = post_params.get('content') if isinstance(post_params, dict) else None
                        res = self.api_save_dict(name, content)
                        return self.get_receive_data(200, json.dumps(res, ensure_ascii=False))
                    if api_action == 'save_config':
                        # post_params expected to be JSON object representing config
                        if isinstance(post_params, dict):
                            res = self.api_save_config(post_params)
                        else:
                            res = {'ok': False, 'error': 'Invalid payload'}
                        return self.get_receive_data(200, json.dumps(res, ensure_ascii=False))

            
            if method == "GET":
                self.log(data=f"Client {addr[0] + ':' + str(addr[1])} connected    {method} {full_path}")
                print(f"Client {addr[0] + ':' + str(addr[1])} sent a request   {method} {full_path}")
                
                if path == "/":
                    try:
                        with open(self.base_path + self.index_file, "r", encoding="utf-8") as f:
                            data = f.read()
                        # 处理模板
                        processed_data = self.process_html_template(data, get_params, post_params)
                        return self.get_receive_data(200, processed_data)
                    except FileNotFoundError:
                        self.log(level="ERROR", data=f"Index file {self.index_file} not found")
                        return self.get_receive_data(404, self.ERROR_PAGE.replace("%code%", "404").replace("%message%", "Index file not found"))
                else:
                    try:
                        with open(self.base_path + path[1:], "r", encoding="utf-8") as f:
                            data = f.read()
                        # 处理模板
                        processed_data = self.process_html_template(data, get_params, post_params)
                        return self.get_receive_data(200, processed_data)
                    except FileNotFoundError:
                        return self.get_receive_data(404, self.ERROR_PAGE.replace("%code%", "404").replace("%message%", "File not found"))

            elif method == "POST":
                self.log(data=f"Client {addr[0] + ':' + str(addr[1])} connected    {method} {path}")
                print(f"Client {addr[0] + ':' + str(addr[1])} sent a request   {method} {path}")
                
                try:
                    if path == "/":
                        with open(self.base_path + self.index_file, "r", encoding="utf-8") as f:
                            data = f.read()
                    else:
                        with open(self.base_path + path[1:], "r", encoding="utf-8") as f:
                            data = f.read()
                    
                    # 处理模板
                    processed_data = self.process_html_template(data, get_params, post_params)
                    return self.get_receive_data(200, processed_data)
                except FileNotFoundError:
                    return self.get_receive_data(404, self.ERROR_PAGE.replace("%code%", "404").replace("%message%", "File not found"))
            else:
                return self.get_receive_data(400, self.ERROR_PAGE.replace("%code%", "400").replace("%message%", "Bad Request"))
                
        except Exception as e:
            self.log(level="ERROR", data=str(e))
            return self.get_receive_data(500, self.ERROR_PAGE.replace("%code%", "500").replace("%message%", "Internal Server Error"))

    def log(self, level=None, data=None, path=None):
        if path is None:
            path = self.path
        if level is None:
            level = "INFO"
        if data is None:
            self.log(level="ERROR", data="data cannot be None")
            raise ValueError("data cannot be None")
        try:
            with open(f"{path}/log.lst", "a") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}] [{level}] : {data}\n")
        except FileNotFoundError:
            self.log(level="ERROR", data=f"Log file not found in {path}")

    def handle_client(self, c, addr):
        data = c.recv(1024 ** 2).decode("utf-8")
        response = self.responese(data, addr)
        c.send(response.encode("utf-8"))
        c.close()

    def run_server(self, host = None, port = None):
            if self.host is None or self.port is None and host is None and port is None:
                self.log(level="ERROR", data="Server setting is not complete")
                raise ValueError("Server setting is not complete")
            elif host is None and port is None:
                host = self.host
                port = self.port
            else:
                self.host = host
                self.port = port
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((host, port))
            s.listen(5)
            self.log(data=f"Server is running on http://{host}:{port}")
            print(f"Server is running on http://{host}:{port}")

            while True:
                try:
                    c, addr = s.accept()
                    threading.Thread(target=self.handle_client, args=(c, addr)).start()
                except Exception as e:
                    self.log(level="ERROR", data=str(e))
                    print(str(e))
                    s.close()
HTTPServer = Server()
HTTPServer.run_server()