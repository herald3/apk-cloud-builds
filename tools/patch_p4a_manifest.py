"""Adds the VpnService declaration to python-for-android's AndroidManifest template (run by the GitHub workflow)."""
import pathlib
import sys

SERVICE = """    <service android:name="org.aminium.aminiumstudio.AminiumVpnService"
        android:permission="android.permission.BIND_VPN_SERVICE"
        android:exported="false">
        <intent-filter>
            <action android:name="android.net.VpnService"/>
        </intent-filter>
    </service>
"""

root = pathlib.Path(sys.argv[1])
files = sorted(root.rglob("AndroidManifest.tmpl.xml"))
if not files:
    sys.exit("AndroidManifest.tmpl.xml not found under %s" % root)
for f in files:
    text = f.read_text(encoding="utf-8")
    if "AminiumVpnService" in text:
        print("already patched:", f)
        continue
    if text.count("</application>") != 1:
        sys.exit("unexpected manifest template layout: %s" % f)
    f.write_text(text.replace("</application>", SERVICE + "    </application>", 1), encoding="utf-8")
    print("patched:", f)
