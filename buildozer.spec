[app]
title = Aminium Studio
package.name = aminiumstudio
package.domain = org.aminium

source.dir = .
source.include_exts = py,png,jpg,kv,atlas,zip,json,txt,md,yml
source.include_patterns = aminium-pages.zip
source.exclude_dirs = bin,.buildozer,.github,venv,__pycache__,.git

version = 1.0.0

requirements = python3,kivy==2.3.0,requests,pysocks,qrcode,certifi,pillow,pyjnius,urllib3,idna,charset-normalizer

orientation = portrait
fullscreen = 0

# Optional app icon: put icon.png next to main.py in the repo, then remove the # below.
#icon.filename = %(source.dir)s/icon.png

android.permissions = INTERNET,ACCESS_NETWORK_STATE

android.api = 33
android.minapi = 24
android.ndk = 25b
android.archs = arm64-v8a

android.allow_backup = True
android.accept_sdk_license = True

p4a.branch = v2024.01.21

[buildozer]
log_level = 2
warn_on_root = 1
