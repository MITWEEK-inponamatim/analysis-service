"""YARA rules for Android malware detection."""

# Community-sourced rules for common Android malware families
# Sources: Koodous, reversinglabs, custom Tria stealer patterns

ANDROID_MALWARE_RULES = """
rule TelegramStealer : stealer
{
    meta:
        description = "Detects Telegram-based OTP/SMS stealer"
        family = "tria_stealer"
        severity = "critical"
    strings:
        $bot1 = "api.telegram.org/bot" ascii wide
        $bot2 = "sendMessage" ascii wide
        $bot3 = "chat_id" ascii wide
        $sms1 = "android.provider.Telephony.SMS_RECEIVED" ascii wide
        $sms2 = "SmsMessage" ascii wide
        $notif = "NotificationListenerService" ascii wide
    condition:
        ($bot1 and $bot2 and $bot3) and ($sms1 or $sms2 or $notif)
}

rule BankingTrojan : banker
{
    meta:
        description = "Detects banking trojan behavior"
        severity = "critical"
    strings:
        $bank1 = /com\\..*\\.bank/ ascii wide
        $bank2 = "getInstalledPackages" ascii wide
        $overlay1 = "TYPE_SYSTEM_OVERLAY" ascii wide
        $overlay2 = "TYPE_APPLICATION_OVERLAY" ascii wide
        $admin = "DeviceAdminReceiver" ascii wide
    condition:
        ($bank1 and $bank2) and ($overlay1 or $overlay2) and $admin
}

rule SMSForwarder : stealer
{
    meta:
        description = "Detects SMS forwarding malware"
        severity = "high"
    strings:
        $sms1 = "android.permission.SEND_SMS" ascii wide
        $sms2 = "SmsManager.sendTextMessage" ascii wide
        $sms3 = "SMS_RECEIVED" ascii wide
        $net1 = "HttpURLConnection" ascii wide
        $net2 = "OkHttpClient" ascii wide
    condition:
        ($sms1 and $sms2 and $sms3) and ($net1 or $net2)
}

rule OverlayAttack : phishing
{
    meta:
        description = "Detects overlay attack/clickjacking"
        severity = "high"
    strings:
        $overlay1 = "TYPE_SYSTEM_ALERT" ascii wide
        $overlay2 = "TYPE_PHONE" ascii wide
        $overlay3 = "WindowManager.addView" ascii wide
        $pkg = "getInstalledPackages" ascii wide
    condition:
        ($overlay1 or $overlay2) and $overlay3 and $pkg
}

rule NotificationInterceptor : stealer
{
    meta:
        description = "Detects notification interception for OTP"
        severity = "critical"
    strings:
        $notif1 = "NotificationListenerService" ascii wide
        $notif2 = "onNotificationPosted" ascii wide
        $notif3 = "getActiveNotifications" ascii wide
        $net = /(http|https|telegram|bot)/ ascii wide
    condition:
        ($notif1 or $notif2 or $notif3) and $net
}

rule DeviceAdminAbuse : persistence
{
    meta:
        description = "Detects device admin abuse for persistence"
        severity = "high"
    strings:
        $admin1 = "DeviceAdminReceiver" ascii wide
        $admin2 = "lockNow" ascii wide
        $admin3 = "wipeData" ascii wide
        $admin4 = "resetPassword" ascii wide
    condition:
        $admin1 and ($admin2 or $admin3 or $admin4)
}

rule DynamicCodeLoading : evasion
{
    meta:
        description = "Detects dynamic code loading for evasion"
        severity = "medium"
    strings:
        $dex1 = "DexClassLoader" ascii wide
        $dex2 = "PathClassLoader" ascii wide
        $dex3 = "Class.forName" ascii wide
        $reflect = "java.lang.reflect" ascii wide
    condition:
        ($dex1 or $dex2 or $dex3) and $reflect
}

rule AntiAnalysis : evasion
{
    meta:
        description = "Detects anti-analysis techniques"
        severity = "medium"
    strings:
        $debug1 = "isDebuggerConnected" ascii wide
        $emu1 = "generic" ascii wide
        $emu2 = "goldfish" ascii wide
        $emu3 = "emulator" ascii wide
        $root1 = "/system/bin/su" ascii wide
        $root2 = "/system/xbin/su" ascii wide
    condition:
        $debug1 or (($emu1 or $emu2 or $emu3) and 2 of them) or ($root1 or $root2)
}

rule C2Communication : network
{
    meta:
        description = "Detects command-and-control communication"
        severity = "high"
    strings:
        $http1 = "HttpURLConnection" ascii wide
        $http2 = "OkHttpClient" ascii wide
        $url = /https?:\\/\\/[a-z0-9.-]+/ ascii wide
        $cmd = /(execute|run|eval|cmd)/ ascii wide
    condition:
        ($http1 or $http2) and $url and $cmd
}

rule DataExfiltration : stealer
{
    meta:
        description = "Detects data exfiltration patterns"
        severity = "high"
    strings:
        $contact = "ContactsContract" ascii wide
        $sms = "content://sms" ascii wide
        $call = "CallLog" ascii wide
        $device = "getDeviceId" ascii wide
        $net = /(HttpURLConnection|OkHttpClient|Socket)/ ascii wide
    condition:
        ($contact or $sms or $call or $device) and $net
}
"""
