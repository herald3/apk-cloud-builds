package org.aminium.aminiumstudio;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * Android VpnService that feeds the TUN device into Xray-core (libv2ray.aar from AndroidLibXrayLite).
 * The AAR is called through reflection, so this file compiles whatever API version of the AAR is bundled;
 * a mismatch shows up as a readable message in {@link #error} instead of a broken build.
 */
public class AminiumVpnService extends VpnService {
    public static volatile String state = "stopped";   // stopped | starting | running | error
    public static volatile String error = "";
    public static volatile String core = "";

    private ParcelFileDescriptor tun;
    private Object controller;
    private final Object lock = new Object();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if ("STOP".equals(action)) {
            stopVpn();
            stopSelf();
            return START_NOT_STICKY;
        }
        final String cfg = intent == null ? null : intent.getStringExtra("config");
        if (cfg == null || cfg.length() == 0) {
            fail("no config was passed to the VPN service");
            stopSelf();
            return START_NOT_STICKY;
        }
        foreground();
        new Thread(new Runnable() {
            public void run() {
                startVpn(cfg);
            }
        }, "aminium-vpn-start").start();
        return START_NOT_STICKY;
    }

    @Override
    public void onRevoke() {          // the user turned the VPN off from the system
        stopVpn();
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    private void fail(String msg) {
        error = msg;
        state = "error";
    }

    private void foreground() {
        try {
            String ch = "aminium_vpn";
            if (Build.VERSION.SDK_INT >= 26) {
                NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
                nm.createNotificationChannel(new NotificationChannel(ch, "VPN", NotificationManager.IMPORTANCE_LOW));
            }
            Notification.Builder nb = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, ch) : new Notification.Builder(this);
            nb.setContentTitle("Aminium VPN").setContentText("VPN is on").setSmallIcon(android.R.drawable.ic_lock_lock).setOngoing(true);
            Intent open = getPackageManager().getLaunchIntentForPackage(getPackageName());
            if (open != null) {
                nb.setContentIntent(PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT));
            }
            startForeground(1, nb.build());
        } catch (Throwable t) {
            // a missing notification must never stop the VPN
        }
    }

    private static Method find(Class<?> c, String name, int argc) {
        for (Method m : c.getMethods()) {
            if (m.getName().equalsIgnoreCase(name) && m.getParameterTypes().length == argc) {
                return m;
            }
        }
        return null;
    }

    private static Object defaultFor(Class<?> t) {
        if (t == long.class) return Long.valueOf(0);
        if (t == int.class) return Integer.valueOf(0);
        if (t == boolean.class) return Boolean.FALSE;
        return null;
    }

    private void startVpn(String cfg) {
        synchronized (lock) {
            stopVpnLocked();
            state = "starting";
            error = "";
            try {
                Builder b = new Builder();
                b.setSession("Aminium");
                b.setMtu(1500);
                b.addAddress("172.19.0.1", 30);
                b.addRoute("0.0.0.0", 0);
                try {
                    b.addAddress("fdfe:dcba:9876::1", 126);
                    b.addRoute("::", 0);
                } catch (Exception ignored) {
                }
                b.addDnsServer("1.1.1.1");
                b.addDnsServer("8.8.8.8");
                try {
                    b.addDisallowedApplication(getPackageName());   // Xray's own sockets must not re-enter the tunnel
                } catch (Exception ignored) {
                }
                tun = b.establish();
                if (tun == null) {
                    fail("VPN permission was not granted");
                    return;
                }

                try {                                               // older gomobile builds need the context
                    Class<?> seq = Class.forName("go.Seq");
                    Method sc = find(seq, "setContext", 1);
                    if (sc != null) sc.invoke(null, getApplicationContext());
                } catch (Throwable ignored) {
                }

                Class<?> lib = Class.forName("libv2ray.Libv2ray");
                Class<?> cb = Class.forName("libv2ray.CoreCallbackHandler");
                Method init = find(lib, "initCoreEnv", 2);
                if (init != null) init.invoke(null, getFilesDir().getAbsolutePath(), "");
                Method ver = find(lib, "checkVersionX", 0);
                if (ver != null) core = String.valueOf(ver.invoke(null));

                Object handler = Proxy.newProxyInstance(cb.getClassLoader(), new Class<?>[]{cb}, new InvocationHandler() {
                    public Object invoke(Object proxy, Method m, Object[] args) {
                        if (m.getDeclaringClass() == Object.class) {
                            String n = m.getName();
                            if (n.equals("equals")) return Boolean.valueOf(proxy == args[0]);
                            if (n.equals("hashCode")) return Integer.valueOf(System.identityHashCode(proxy));
                            return "AminiumCallback";
                        }
                        return defaultFor(m.getReturnType());
                    }
                });
                Method nc = find(lib, "newCoreController", 1);
                if (nc == null) {
                    fail("libv2ray: newCoreController not found (unsupported core version)");
                    return;
                }
                controller = nc.invoke(null, handler);

                Method start = null;
                for (Method m : controller.getClass().getMethods()) {
                    if (m.getName().equalsIgnoreCase("startLoop")) {
                        Class<?>[] p = m.getParameterTypes();
                        if (p.length == 2 && p[0] == String.class) start = m;
                    }
                }
                if (start == null) {
                    fail("this libv2ray build has no startLoop(config, tunFd): it cannot take a TUN device");
                    return;
                }
                Class<?> fdType = start.getParameterTypes()[1];
                int fd = tun.getFd();
                Object fdArg = fdType == long.class ? (Object) Long.valueOf(fd) : (Object) Integer.valueOf(fd);
                start.invoke(controller, cfg, fdArg);
                state = "running";
            } catch (Throwable t) {
                Throwable c = t.getCause() != null ? t.getCause() : t;
                fail(c.getClass().getSimpleName() + ": " + c.getMessage());
                stopVpnLocked();
                state = "error";
            }
        }
    }

    private void stopVpn() {
        synchronized (lock) {
            stopVpnLocked();
            if (!"error".equals(state)) state = "stopped";
        }
    }

    private void stopVpnLocked() {
        try {
            if (controller != null) {
                Method stop = find(controller.getClass(), "stopLoop", 0);
                if (stop != null) stop.invoke(controller);
            }
        } catch (Throwable ignored) {
        }
        controller = null;
        try {
            if (tun != null) tun.close();
        } catch (Throwable ignored) {
        }
        tun = null;
    }
}
