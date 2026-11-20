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
