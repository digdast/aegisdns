"""
AegisDNS - GitHub Publisher & Showcase Synchronizer
Creates repository digdast/aegisdns via GitHub API and pushes the complete codebase.
"""

import os
import sys
import json
import urllib.request
import ctypes
from ctypes import wintypes
import subprocess

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# 1. Retrieve GitHub Token from Windows Credential Manager
class CREDENTIAL_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ('Keyword', wintypes.LPWSTR),
        ('Flags', wintypes.DWORD),
        ('ValueSize', wintypes.DWORD),
        ('Value', ctypes.POINTER(ctypes.c_byte))
    ]

class CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ('Flags', wintypes.DWORD),
        ('Type', wintypes.DWORD),
        ('TargetName', wintypes.LPWSTR),
        ('Comment', wintypes.LPWSTR),
        ('LastWritten', wintypes.FILETIME),
        ('CredentialBlobSize', wintypes.DWORD),
        ('CredentialBlob', ctypes.POINTER(ctypes.c_byte)),
        ('Persist', wintypes.DWORD),
        ('AttributeCount', wintypes.DWORD),
        ('Attributes', ctypes.POINTER(CREDENTIAL_ATTRIBUTE)),
        ('TargetAlias', wintypes.LPWSTR),
        ('UserName', wintypes.LPWSTR)
    ]

PCREDENTIAL = ctypes.POINTER(CREDENTIAL)
advapi32 = ctypes.windll.advapi32
CredRead = advapi32.CredReadW
CredRead.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(PCREDENTIAL)]
CredRead.restype = wintypes.BOOL
CredFree = advapi32.CredFree
CredFree.argtypes = [ctypes.c_void_p]

p_cred = PCREDENTIAL()
target = 'LegacyGeneric:target=GitHub - https://api.github.com/digdast'
if not CredRead(target, 1, 0, ctypes.byref(p_cred)):
    print("[ERROR] Could not read GitHub token from Windows Credential Manager.")
    sys.exit(1)

token = ctypes.string_at(p_cred.contents.CredentialBlob, p_cred.contents.CredentialBlobSize).decode('utf-8')
CredFree(p_cred)

HEADERS = {
    'Authorization': f'token {token}',
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'AegisDNS-Publisher'
}

REPO_NAME = "aegisdns"
OWNER = "digdast"
REPO_FULL = f"{OWNER}/{REPO_NAME}"

print(f"[*] Checking GitHub repository '{REPO_FULL}'...")

# 2. Check or Create GitHub Repository
check_url = f"https://api.github.com/repos/{REPO_FULL}"
repo_exists = False
try:
    req = urllib.request.Request(check_url, headers=HEADERS)
    with urllib.request.urlopen(req) as resp:
        if resp.status == 200:
            repo_exists = True
            print(f"  ✓ Repository '{REPO_FULL}' already exists.")
except urllib.error.HTTPError as e:
    if e.code == 404:
        repo_exists = False
    else:
        print(f"  [!] HTTP Error checking repo: {e}")

if not repo_exists:
    print(f"[*] Creating repository '{REPO_FULL}' on GitHub...")
    create_url = "https://api.github.com/user/repos"
    payload = {
        "name": REPO_NAME,
        "description": "Next-Gen Recursive DNS Resolver, RFC 8484 DNS-over-HTTPS (DoH), and Threat Sinkhole with Executive Glassmorphic UI.",
        "private": False,
        "has_issues": True,
        "has_projects": True,
        "has_wiki": False
    }
    req = urllib.request.Request(create_url, data=json.dumps(payload).encode('utf-8'), headers=HEADERS, method='POST')
    try:
        with urllib.request.urlopen(req) as resp:
            print(f"  ✓ Successfully created GitHub repository '{REPO_FULL}'!")
    except urllib.error.HTTPError as e:
        print(f"  [ERROR] Failed to create repo: {e.read().decode('utf-8')}")
        sys.exit(1)

# Set Topics for high discoverability and stars
print("[*] Setting repository topics...")
topics_url = f"https://api.github.com/repos/{REPO_FULL}/topics"
topics_payload = {
    "names": [
        "dns",
        "dns-over-https",
        "doh",
        "recursive-dns",
        "adblock",
        "adblocking",
        "malware-blocking",
        "pi-hole",
        "adguard-home",
        "unbound",
        "fastapi",
        "cybersecurity",
        "homelab",
        "python"
    ]
}
topics_headers = {**HEADERS, 'Accept': 'application/vnd.github.mercy-preview+json'}
try:
    req = urllib.request.Request(topics_url, data=json.dumps(topics_payload).encode('utf-8'), headers=topics_headers, method='PUT')
    with urllib.request.urlopen(req) as resp:
        print("  ✓ Repository topics set for maximum discoverability!")
except Exception as e:
    print(f"  [!] Could not set topics: {e}")

# 3. Local Git Commit and Push
print("[*] Initializing local git repository and pushing...")
cwd = r"C:\scripts\aegisdns"

def run_git(cmd):
    p = subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True)
    if p.returncode != 0:
        print(f"Git command failed: {cmd}\nOutput: {p.stdout}\nError: {p.stderr}")
    return p

run_git("git init -b main")
run_git('git config user.name "digdast"')
run_git('git config user.email "efrain.acetech@gmail.com"')
run_git(f'git remote remove origin')
run_git(f'git remote add origin https://{token}@github.com/{REPO_FULL}.git')
run_git("git add .")
run_git('git commit -m "feat: Initial release of AegisDNS - Recursive DoH Resolver & Cyber Command Center"')
push_res = run_git("git push -u origin main --force")

if push_res.returncode == 0:
    print("\n" + "=" * 60)
    print(f"🚀 AegisDNS is now LIVE on GitHub!")
    print(f"🔗 https://github.com/{REPO_FULL}")
    print("=" * 60)
else:
    print(f"[!] Push failed: {push_res.stderr}")
