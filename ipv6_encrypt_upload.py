#!/usr/bin/env python3

import os
import re
import subprocess
import base64
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import requests
from datetime import datetime, timezone

# 配置信息 - 必须修改为您的实际信息
REPO_OWNER = "your_actual_github_username"  # 替换为您的 GitHub 用户名
REPO_NAME = "your_actual_repository_name"   # 替换为您的仓库名
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')    # 从环境变量获取 GitHub Token
ENCRYPTION_PASSWORD = os.getenv('ENCRYPTION_PASSWORD')  # 加密密码
ENCRYPTED_FILENAME = "encrypted_ipv6.bin"   # 加密文件名
CACHE_FILE = os.path.expanduser("~/.ipv6_cache")  # 本地缓存文件路径

def get_ipv6_address():
    """获取本机IPv6地址（非本地链路地址）"""
    output = subprocess.check_output(['ip', '-6', 'addr']).decode()
    # 匹配全局IPv6地址（以2或3开头）
    matches = re.findall(r'inet6 (2[0-9a-f:]+|3[0-9a-f:]+)/\d+', output)
    return matches[0] if matches else None

def process_password(password):
    """对密码进行4次base64编码后取SHA256哈希"""
    processed = password.encode()
    for _ in range(4):
        processed = base64.b64encode(processed)
    return hashlib.sha256(processed).digest()  # 返回32字节密钥

def encrypt_data(data, password):
    """使用AES-256-GCM加密数据"""
    key = process_password(password)
    nonce = get_random_bytes(12)  # GCM推荐12字节nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return nonce + tag + ciphertext  # 组合成: nonce(12) + tag(16) + ciphertext

def get_cached_ip():
    """从本地缓存文件中获取上次上传的IP地址"""
    if not os.path.exists(CACHE_FILE):
        return None
    
    try:
        with open(CACHE_FILE, 'r') as f:
            return f.read().strip()
    except Exception as e:
        print(f"读取缓存文件失败: {str(e)}")
        return None

def update_cache(ip):
    """更新本地缓存文件"""
    try:
        with open(CACHE_FILE, 'w') as f:
            f.write(ip)
        print(f"缓存已更新: {ip}")
        return True
    except Exception as e:
        print(f"更新缓存失败: {str(e)}")
        return False

def upload_to_github(content, filename):
    """上传文件到GitHub仓库"""
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{filename}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    
    try:
        # 检查文件是否存在（获取SHA）
        r = requests.get(url, headers=headers)
        sha = None
        if r.status_code == 200:
            sha = r.json().get('sha')
            print(f"文件已存在，获取到 SHA: {sha[:10]}...")
        elif r.status_code != 404:
            r.raise_for_status()
        
        # 创建/更新文件
        data = {
            "message": f"Update encrypted IPv6 - {datetime.now(timezone.utc).isoformat()}",
            "content": base64.b64encode(content).decode('utf-8'),
            "sha": sha
        }
        
        r = requests.put(url, headers=headers, json=data)
        r.raise_for_status()
        print(f"文件 {filename} 上传成功！")
        return True
    except requests.exceptions.HTTPError as e:
        print(f"HTTP 错误 ({e.response.status_code}): {e.response.text}")
        return False
    except Exception as e:
        print(f"上传失败: {str(e)}")
        return False

def check_ip_change(new_ip):
    """检查IP是否变动：使用本地缓存进行比较"""
    cached_ip = get_cached_ip()
    
    if cached_ip is None:
        print("无缓存记录，需要上传")
        return True
    
    print(f"缓存IP: {cached_ip}")
    print(f"当前IP: {new_ip}")
    return cached_ip != new_ip

if __name__ == "__main__":
    # 验证环境变量
    if not GITHUB_TOKEN or not ENCRYPTION_PASSWORD:
        raise EnvironmentError("缺少 GITHUB_TOKEN 或 ENCRYPTION_PASSWORD 环境变量")
    
    # 获取IPv6地址
    ipv6 = get_ipv6_address()
    if not ipv6:
        raise RuntimeError("未找到公共 IPv6 地址")
    
    print(f"获取到 IPv6 地址: {ipv6}")
    
    # 检查IP变动
    if not check_ip_change(ipv6):
        print("IP地址未变化，无需上传")
        exit(0)
    
    # 加密并上传
    encrypted = encrypt_data(ipv6, ENCRYPTION_PASSWORD)
    print(f"加密数据大小: {len(encrypted)} 字节")
    
    if upload_to_github(encrypted, ENCRYPTED_FILENAME):
        # 上传成功后更新本地缓存
        update_cache(ipv6)
        print("操作成功完成！")
    else:
        print("操作失败，请检查错误信息")
        exit(1)
