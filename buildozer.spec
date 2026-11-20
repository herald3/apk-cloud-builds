[app]
p4a.branch = v2024.01.21
title = Aminium Studio
package.name = aminiumstudio
package.domain = org.aminium
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,zip,json,md
source.exclude_dirs = .github,bin,.buildozer,venv,__pycache__
version = 1.0.0
requirements = python3,kivy==2.3.0,requests==2.31.0,urllib3==1.26.18,chardet==3.0.4,idna==3.6,certifi,qrcode==7.4.2,pypng,typing_extensions,pyjnius,android,charset-normalizer
orientation = portrait
fullscreen = 0
icon.filename = %(source.dir)s/icon.png
presplash.filename = %(source.dir)s/presplash.png
android.presplash_color = #0a0f1f
android.permissions = INTERNET,ACCESS_NETWORK_STATE,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE
android.api = 33
android.minapi = 24
android.ndk = 25b
android.archs = arm64-v8a
android.accept_sdk_license = True
android.allow_backup = False

[buildozer]
log_level = 2
warn_on_root = 0
