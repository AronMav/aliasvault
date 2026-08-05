package net.aliasvault.app

import android.app.Activity
import android.app.Application
import android.content.res.Configuration
import android.os.Bundle
import android.view.WindowManager
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.facebook.react.PackageList
import com.facebook.react.ReactApplication
import com.facebook.react.ReactHost
import com.facebook.react.ReactNativeApplicationEntryPoint.loadReactNative
import com.facebook.react.common.ReleaseLevel
import com.facebook.react.defaults.DefaultNewArchitectureEntryPoint
import expo.modules.ApplicationLifecycleDispatcher
import expo.modules.ExpoReactHostFactory
import net.aliasvault.app.nativevaultmanager.NativeVaultManagerPackage
import net.aliasvault.app.vaultstore.VaultStore

/**
 * The main application class.
 */
class MainApplication : Application(), ReactApplication {

    override val reactHost: ReactHost by lazy {
        ExpoReactHostFactory.getDefaultReactHost(
            context = applicationContext,
            packageList = PackageList(this).packages.apply {
                // Packages that cannot be autolinked yet can be added manually here, for example:
                // add(MyReactNativePackage())
                add(NativeVaultManagerPackage())
            },
        )
    }

    override fun onCreate() {
        super.onCreate()
        @Suppress("SwallowedException")
        DefaultNewArchitectureEntryPoint.releaseLevel = try {
            ReleaseLevel.valueOf(BuildConfig.REACT_NATIVE_RELEASE_LEVEL.uppercase())
        } catch (e: IllegalArgumentException) {
            ReleaseLevel.STABLE
        }
        loadReactNative(this)
        ApplicationLifecycleDispatcher.onApplicationCreate(this)

        // Keep vault contents out of screenshots and screen recordings
        setupSecureWindowFlag()

        // Setup process lifecycle observer for auto-lock functionality
        setupProcessLifecycleObserver()
    }

    /**
     * Mark every activity's window as secure.
     *
     * Without this the system snapshots the screen for the app switcher, and screen recorders
     * and remote-assistance tools can capture it, so credentials on screen leak into places the
     * user did not intend. Applying it here rather than in each activity means an activity added
     * later is covered without anyone having to remember.
     */
    private fun setupSecureWindowFlag() {
        registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                activity.window.setFlags(
                    WindowManager.LayoutParams.FLAG_SECURE,
                    WindowManager.LayoutParams.FLAG_SECURE,
                )
            }

            override fun onActivityStarted(activity: Activity) = Unit
            override fun onActivityResumed(activity: Activity) = Unit
            override fun onActivityPaused(activity: Activity) = Unit
            override fun onActivityStopped(activity: Activity) = Unit
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
            override fun onActivityDestroyed(activity: Activity) = Unit
        })
    }

    /**
     * Setup process-level lifecycle observer to track when the app backgrounds/foregrounds.
     *
     * If the instance doesn't exist yet (e.g., app backgrounded before React Native initialized),
     * we skip the lifecycle callbacks. This is safe because there's no vault to lock yet.
     */
    private fun setupProcessLifecycleObserver() {
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStop(owner: LifecycleOwner) {
                // Called when app goes to background (all activities stopped)
                try {
                    // Only notify existing instance
                    val vaultStore = VaultStore.getExistingInstance()
                    if (vaultStore != null) {
                        vaultStore.vaultAuth.onAppBackgrounded()
                    } else {
                        android.util.Log.d("MainApplication", "VaultStore not initialized yet, skipping background callback")
                    }
                } catch (e: Exception) {
                    android.util.Log.e("MainApplication", "Error handling app background", e)
                }
            }

            override fun onStart(owner: LifecycleOwner) {
                // Called when app comes to foreground (at least one activity visible)
                try {
                    // Only notify existing instance
                    val vaultStore = VaultStore.getExistingInstance()
                    if (vaultStore != null) {
                        vaultStore.vaultAuth.onAppForegrounded()
                    } else {
                        android.util.Log.d("MainApplication", "VaultStore not initialized yet, skipping foreground callback")
                    }
                } catch (e: Exception) {
                    android.util.Log.e("MainApplication", "Error handling app foreground", e)
                }
            }
        })
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        ApplicationLifecycleDispatcher.onConfigurationChanged(this, newConfig)
    }
}
