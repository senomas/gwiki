package com.gwiki.app.webview

import android.content.Context
import android.webkit.CookieManager
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import com.gwiki.app.data.GwikiPrefs
import okhttp3.Cache
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File

/**
 * Intercepts all WebView requests through OkHttp so responses are cached on disk.
 * Falls back to cache when offline via [OfflineInterceptor].
 * Cookies are read from Android's CookieManager and forwarded to OkHttp manually.
 */
class GwikiWebViewClient(
    context: Context,
    prefs: GwikiPrefs,
    private val onEditUrl: (String) -> Unit,
) : WebViewClient() {

    val okhttp: OkHttpClient = run {
        val cacheDir = File(context.cacheDir, "gwiki-http")
        val cacheBytes = prefs.cacheMb.toLong() * 1024 * 1024
        OkHttpClient.Builder()
            .cache(Cache(cacheDir, cacheBytes))
            .addInterceptor(OfflineInterceptor(context))
            .build()
    }

    override fun shouldInterceptRequest(
        view: WebView,
        request: WebResourceRequest,
    ): WebResourceResponse? {
        val url = request.url.toString()

        // Only intercept http/https GET requests for the wiki server
        if (request.method != "GET" || (!url.startsWith("http://") && !url.startsWith("https://"))) {
            return null
        }

        return try {
            // Sync cookies from WebView CookieManager into OkHttp
            val androidCookies = CookieManager.getInstance().getCookie(url)
            val okRequest = Request.Builder()
                .url(url)
                .apply {
                    request.requestHeaders.forEach { (k, v) -> header(k, v) }
                    if (androidCookies != null) header("Cookie", androidCookies)
                }
                .build()

            val response = okhttp.newCall(okRequest).execute()
            val contentType = response.header("Content-Type", "text/html") ?: "text/html"
            val (mime, encoding) = parseMimeEncoding(contentType)

            WebResourceResponse(mime, encoding, response.code, response.message.ifEmpty { "OK" },
                response.headers.toMap(), response.body?.byteStream())
        } catch (e: Exception) {
            null // Let WebView handle it
        }
    }

    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
        val url = request.url.toString()
        if (url.contains("/edit") || url.contains("/notes/new")) {
            onEditUrl(url)
            return true
        }
        return false
    }

    private fun parseMimeEncoding(contentType: String): Pair<String, String> {
        val parts = contentType.split(";").map { it.trim() }
        val mime = parts.firstOrNull() ?: "text/html"
        val charset = parts.firstOrNull { it.startsWith("charset=") }
            ?.removePrefix("charset=") ?: "utf-8"
        return mime to charset
    }
}

private fun okhttp3.Headers.toMap(): Map<String, String> =
    names().associateWith { name -> values(name).joinToString(", ") }
