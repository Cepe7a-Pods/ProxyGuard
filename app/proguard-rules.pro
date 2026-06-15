# MTProto relay — keep crypto classes
-keep class com.proxyguard.relay.** { *; }
-keep class com.proxyguard.proxy.** { *; }

# Gson для ProxyRepository
-keepattributes Signature
-keepattributes *Annotation*
-dontwarn sun.misc.**
-keep class com.google.gson.** { *; }
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer
-keepclassmembers,allowobfuscation class * {
  @com.google.gson.annotations.SerializedName <fields>;
}

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**

# WorkManager
-keep class androidx.work.** { *; }
