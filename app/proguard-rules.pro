# ─── MTProto relay — не трогаем крипто-ядро ──────────────────────────────────
-keep class com.proxyguard.relay.** { *; }
-keep class com.proxyguard.proxy.** { *; }

# ─── Gson (ProxyRepository) ──────────────────────────────────────────────────
-keepattributes Signature
-keepattributes *Annotation*
-keep class com.google.gson.** { *; }
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer
-keepclassmembers,allowobfuscation class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# ─── OkHttp ──────────────────────────────────────────────────────────────────
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }

# ─── WorkManager ─────────────────────────────────────────────────────────────
-keep class androidx.work.** { *; }
-keepclassmembers class * extends androidx.work.Worker { *; }
-keepclassmembers class * extends androidx.work.CoroutineWorker { *; }
-keepclassmembers class * extends androidx.work.ListenableWorker {
    public <init>(android.content.Context, androidx.work.WorkerParameters);
}

# ─── security-crypto тянет Google Tink, который ссылается на errorprone ──────
# Эти аннотации нужны только при компиляции, в runtime не используются
-dontwarn com.google.errorprone.annotations.**
-dontwarn com.google.errorprone.annotations.concurrent.**
-dontwarn javax.annotation.**
-dontwarn javax.annotation.concurrent.**
-dontwarn org.checkerframework.**
-dontwarn afu.org.checkerframework.**
-dontwarn com.google.crypto.tink.subtle.**
