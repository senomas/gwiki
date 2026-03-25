package com.gwiki.app.webview

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import okhttp3.CacheControl
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import java.io.IOException

/**
 * On network failure, retries the request forcing the OkHttp cache.
 * This gives best-effort offline behaviour for previously cached pages.
 */
class OfflineInterceptor(private val context: Context) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        return try {
            val response = chain.proceed(request)
            // If online, add cache header so pages are cached for later offline use
            if (isOnline()) {
                response.newBuilder()
                    .header("Cache-Control", "public, max-age=600")
                    .build()
            } else {
                forceCached(chain, request)
            }
        } catch (e: IOException) {
            forceCached(chain, request)
        }
    }

    private fun forceCached(chain: Interceptor.Chain, request: Request): Response {
        val offlineRequest = request.newBuilder()
            .cacheControl(CacheControl.FORCE_CACHE)
            .build()
        return chain.proceed(offlineRequest)
    }

    private fun isOnline(): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }
}
