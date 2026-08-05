# Add project specific ProGuard rules here.
# By default, the flags in this file are appended to flags specified
# in /usr/local/Cellar/android-sdk/24.3.3/tools/proguard/proguard-android.txt
# You can edit the include path and order by changing the proguardFiles
# directive in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# react-native-reanimated
-keep class com.swmansion.reanimated.** { *; }
-keep class com.facebook.react.turbomodule.** { *; }

# ---------------------------------------------------------------------------
# Rust core (UniFFI over JNA)
#
# Minification is off by default (android.enableProguardInReleaseBuilds), so
# none of this is exercised yet. The rules are here so that whoever turns it on
# starts from a working position rather than from a crash in the crypto path.
#
# JNA binds Java to native code by name: it reads Structure field names and
# their declaration order to lay out structs, resolves Library methods to
# native symbols, and calls Callback implementations from native code. Renaming
# or reordering any of that breaks the binding at runtime, and only at runtime,
# so it would surface as a vault that will not unlock rather than as a build
# error. The generated bindings in uniffi.aliasvault_core use all three.
# ---------------------------------------------------------------------------
-keep class uniffi.aliasvault_core.** { *; }
-keep class com.sun.jna.** { *; }
-keep interface com.sun.jna.** { *; }
-keep class * extends com.sun.jna.Structure { *; }
-keep class * implements com.sun.jna.Callback { *; }
-keep interface * extends com.sun.jna.Callback { *; }
-keep class * implements com.sun.jna.Library { *; }
-keep interface * extends com.sun.jna.Library { *; }
-keep class * extends com.sun.jna.IntegerType { *; }

# JNA reflects over these at load time and warns about optional AWT types that
# are absent on Android.
-dontwarn java.awt.**
-dontwarn com.sun.jna.**

# Add any project specific keep options here:
