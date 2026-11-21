# Aminium Studio (Android / Kivy)

Same engine as the desktop app (scanner, Cloudflare deploy, panel, configs, QR) with a touch UI.

## Build the APK on GitHub
1. `aminium-pages.zip` is already included next to `main.py` and is bundled into the APK (you can also pick another zip from the phone in step 3 > Advanced > Pick zip).
2. Upload everything (including the hidden `.github` folder) to a new GitHub repo.
3. Open the **Actions** tab -> *Build Android APK* (first build takes ~25-40 min).
4. Download the artifact **AminiumStudio-apk**, unzip, install the `.apk`.

## Notes
- Token and settings are stored privately inside the app.
- "Save all files + QR" writes to the app's folder and, when allowed, to `Download/AminiumStudio`.
- Keep the app open (screen stays on) while scanning / building.
- Desktop test: `pip install kivy requests qrcode certifi` then `python main.py`.

- Config name: set it in step 3 ("Config name") or change it later in step 4 ("Apply name"). Links look like `NAME-vless-IP-port`.

## VPN tab
- Every build saves its configs on the **VPN** tab; once configs exist the app opens on that tab.
- *Real ping*: TLS + WebSocket upgrade through the config (with the Patt fragment when that switch is on). *TCP ping*: connect time.
- *Patt disguise* turns every link into the Patt form (fp=unsafe, alpn=http/1.1, cs, fm). *Copy Xray JSON* gives a full Xray-core client config.
- **Built-in VPN**: `java/.../AminiumVpnService.java` (Android VpnService) feeds the TUN device into Xray-core from `libv2ray.aar`
  (downloaded by the workflow from the AndroidLibXrayLite releases). Connect asks for the VPN permission, the key icon appears.
  The workflow prints the real libv2ray API (`javap`) - if Connect shows an error, send that text + the app log.
- Local build needs `libs/libv2ray.aar`, a `p4a_src` checkout and `python3 tools/patch_p4a_manifest.py p4a_src` (the workflow does all of it).
