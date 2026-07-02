package mw.gri.android;

import android.annotation.SuppressLint;
import android.app.*;
import android.content.Context;
import android.content.Intent;
import android.os.*;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;

import java.util.List;

import static android.app.Notification.EXTRA_NOTIFICATION_ID;

public class BackgroundService extends Service {
    private static final String TAG = BackgroundService.class.getSimpleName();

    private PowerManager.WakeLock mWakeLock;

    private final Handler mHandler = new Handler(Looper.getMainLooper());
    private boolean mStopped = false;

    private static final int NOTIFICATION_ID = 1;
    // One-shot "payment received" notification, separate from the persistent
    // sync notification above.
    private static final int PAYMENT_NOTIFICATION_ID = 2;
    private static final String PAYMENT_CHANNEL_ID = "PaymentReceived";
    private NotificationCompat.Builder mNotificationBuilder;

    private String mNotificationContentText = "";
    private Boolean mCanStart = null;
    private Boolean mCanStop = null;

    public static final String ACTION_START_NODE = "start_node";
    public static final String ACTION_STOP_NODE = "stop_node";

    private final Runnable mUpdateSyncStatus = new Runnable() {
        @SuppressLint("RestrictedApi")
        @Override
        public void run() {
            if (mStopped) {
                return;
            }
            // Update sync status at notification.
            String syncStatusText = getSyncStatusText();
            boolean textChanged = !mNotificationContentText.equals(syncStatusText);
            if (textChanged) {
                mNotificationContentText = syncStatusText;
                mNotificationBuilder.setContentText(mNotificationContentText);
                mNotificationBuilder.setStyle(new NotificationCompat.BigTextStyle().bigText(mNotificationContentText));
            }

            // Send broadcast to MainActivity if exit from the app is needed after node stop.
            if (exitAppAfterNodeStop()) {
                sendBroadcast(new Intent(MainActivity.STOP_APP_ACTION));
                mStopped = true;
            }

            if (!mStopped) {
                boolean canStart = canStartNode();
                boolean canStop = canStopNode();

                boolean buttonsChanged = mCanStart == null || mCanStop == null ||
                        mCanStart != canStart || mCanStop != canStop;
                mCanStart = canStart;
                mCanStop = canStop;
                if (buttonsChanged) {
                    mNotificationBuilder.mActions.clear();

                    // Set up buttons to start/stop node.
                    Intent startStopIntent = new Intent(BackgroundService.this, NotificationActionsReceiver.class);
                    if (Build.VERSION.SDK_INT > 25) {
                        startStopIntent.putExtra(EXTRA_NOTIFICATION_ID, NOTIFICATION_ID);
                    }
                    // Goblin's background job is the light Nostr-over-Nym payment
                    // listen (the "Listening for payments" status); the heavy
                    // integrated node is never STARTED from this notification --
                    // Goblin defaults to an external node, so the GRIM "Enable"
                    // action is removed. Only offer STOP as a safety valve if the
                    // node is somehow already running (started elsewhere).
                    if (canStop) {
                        startStopIntent.setAction(ACTION_STOP_NODE);
                        PendingIntent i = PendingIntent
                                .getBroadcast(BackgroundService.this, 1, startStopIntent, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_ONE_SHOT);
                        mNotificationBuilder.addAction(R.drawable.ic_stop, getStopText(), i);
                    }
                }

                // Update notification.
                if (textChanged || buttonsChanged) {
                    NotificationManager manager = getSystemService(NotificationManager.class);
                    manager.notify(NOTIFICATION_ID, mNotificationBuilder.build());
                }

                // Repeat notification update.
                mHandler.postDelayed(this, 1000);
            }
        }
    };

    @SuppressLint({"WakelockTimeout", "UnspecifiedRegisterReceiverFlag"})
    @Override
    public void onCreate() {
        if (mStopped) {
            return;
        }

        // Prevent CPU to sleep at background.
        PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
        mWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, TAG);
        mWakeLock.acquire();

        // Create channel to show notifications.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel notificationChannel = new NotificationChannel(
                    TAG, TAG, NotificationManager.IMPORTANCE_LOW
            );

            NotificationManager manager = getSystemService(NotificationManager.class);
            manager.createNotificationChannel(notificationChannel);
        }

        // Show notification with sync status.
        Intent i = getPackageManager().getLaunchIntentForPackage(this.getPackageName());
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE);
        try {
            mNotificationBuilder = new NotificationCompat.Builder(this, TAG)
                    .setContentTitle(this.getSyncTitle())
                    .setContentText(this.getSyncStatusText())
                    .setStyle(new NotificationCompat.BigTextStyle().bigText(this.getSyncStatusText()))
                    .setSmallIcon(R.drawable.ic_stat_name)
                    .setPriority(NotificationCompat.PRIORITY_MAX)
                    .setContentIntent(pendingIntent);
        } catch (UnsatisfiedLinkError e) {
            return;
        }
        Notification notification = mNotificationBuilder.build();

        // Start service at foreground state to prevent killing by system.
        startForeground(NOTIFICATION_ID, notification);

        // Update sync status at notification.
        mHandler.post(mUpdateSyncStatus);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        onStop();
        super.onTaskRemoved(rootIntent);
    }

    @Override
    public void onDestroy() {
        onStop();
        super.onDestroy();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    public void onStop() {
        mStopped = true;

        // Stop updating the notification.
        mHandler.removeCallbacks(mUpdateSyncStatus);
        clearNotification();

        // Remove service from foreground state.
        stopForeground(Service.STOP_FOREGROUND_REMOVE);

        // Release wake lock to allow CPU to sleep at background.
        if (mWakeLock != null && mWakeLock.isHeld()) {
            mWakeLock.release();
            mWakeLock = null;
        }
    }

    // Remove notification.
    private void clearNotification() {
        NotificationManager notificationManager = getSystemService(NotificationManager.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            notificationManager.deleteNotificationChannel(TAG);
        }
        notificationManager.cancel(NOTIFICATION_ID);
    }

    // Show a one-shot "payment received" notification (id=2), separate from
    // the persistent sync notification (id=1). Called from native code via
    // MainActivity when a payment slatepack is received over nostr, possibly
    // while the app is backgrounded. Localization of the fixed strings is a
    // follow-up (text is composed here at Java side).
    public static void notifyPaymentReceived(Context context, String name, String amount) {
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        if (manager == null) {
            return;
        }
        // High-importance channel so the notification pops with sound + vibration.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    PAYMENT_CHANNEL_ID, "Payments", NotificationManager.IMPORTANCE_HIGH
            );
            manager.createNotificationChannel(channel);
        }
        Intent i = context.getPackageManager().getLaunchIntentForPackage(context.getPackageName());
        PendingIntent pendingIntent = PendingIntent.getActivity(context, 0, i, PendingIntent.FLAG_IMMUTABLE);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, PAYMENT_CHANNEL_ID)
                .setContentTitle("Payment received")
                .setContentText(name + " paid " + amount + " ツ")
                .setSmallIcon(R.drawable.ic_stat_name)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setDefaults(NotificationCompat.DEFAULT_ALL)
                .setContentIntent(pendingIntent);
        try {
            manager.notify(PAYMENT_NOTIFICATION_ID, builder.build());
        } catch (SecurityException e) {
            // POST_NOTIFICATIONS not granted: skip the notification, never the payment.
        }
    }

    // Start the service.
    public static void start(Context c) {
        if (!isServiceRunning(c)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                ContextCompat.startForegroundService(c, new Intent(c, BackgroundService.class));
            } else {
                c.startService(new Intent(c, BackgroundService.class));
            }
        }
    }

    // Stop the service.
    public static void stop(Context context) {
        context.stopService(new Intent(context, BackgroundService.class));
    }

    // Check if service is running.
    private static boolean isServiceRunning(Context context) {
        ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        List<ActivityManager.RunningServiceInfo> services = activityManager.getRunningServices(Integer.MAX_VALUE);

        for (ActivityManager.RunningServiceInfo runningServiceInfo : services) {
            if (runningServiceInfo.service.getClassName().equals(BackgroundService.class.getName())) {
                return true;
            }
        }

        return false;
    }

    // Get sync status text for notification.
    private native String getSyncStatusText();
    // Get sync title text for notification.
    private native String getSyncTitle();

    // Get start text for notification.
    private native String getStartText();
    // Get stop text for notification.
    private native String getStopText();

    // Check if start node is possible.
    private native boolean canStartNode();
    // Check if stop node is possible.
    private native boolean canStopNode();

    // Check if app from the app is needed after node stop.
    private native boolean exitAppAfterNodeStop();
}