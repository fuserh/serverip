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

def upload_to_github(content, filename):
    """上传文件到GitHub仓库"""
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{filename}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    
    print(f"尝试访问 URL: {url}")
    
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

if __name__ == "__main__":
    # 验证环境变量
    if not GITHUB_TOKEN or not ENCRYPTION_PASSWORD:
        raise EnvironmentError("缺少 GITHUB_TOKEN 或 ENCRYPTION_PASSWORD 环境变量")
    
    # 获取并加密IPv6
    ipv6 = get_ipv6_address()
    if not ipv6:
        raise RuntimeError("未找到公共 IPv6 地址")
    
    print(f"获取到 IPv6 地址: {ipv6}")
    encrypted = encrypt_data(ipv6, ENCRYPTION_PASSWORD)
    print(f"加密数据大小: {len(encrypted)} 字节")
    
    # 上传到GitHub
    if upload_to_github(encrypted, "encrypted_ipv6.bin"):
        print("操作成功完成！")
    else:
        print("操作失败，请检查错误信息")
        exit(1)
