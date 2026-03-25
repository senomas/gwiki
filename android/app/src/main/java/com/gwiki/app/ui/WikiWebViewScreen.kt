package com.gwiki.app.ui

import android.annotation.SuppressLint
import android.webkit.WebSettings
import android.webkit.WebView
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.gwiki.app.data.Prefs
import com.gwiki.app.webview.GwikiWebViewClient

@SuppressLint("SetJavaScriptEnabled")
@Composable
fun WikiWebViewScreen(
    prefs: Prefs,
    onEditUrl: (String) -> Unit,
) {
    val gwikiPrefs by prefs.flow.collectAsState(initial = null)
    var isOffline by remember { mutableStateOf(false) }
    var webViewClient by remember { mutableStateOf<GwikiWebViewClient?>(null) }

    Box(modifier = Modifier.fillMaxSize()) {
        gwikiPrefs?.let { p ->
            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { ctx ->
                    WebView(ctx).apply {
                        val client = GwikiWebViewClient(ctx, p) { editUrl ->
                            onEditUrl(editUrl)
                        }
                        webViewClient = client
                        setWebViewClient(client)
                        settings.apply {
                            javaScriptEnabled = true
                            domStorageEnabled = true
                            cacheMode = WebSettings.LOAD_DEFAULT
                            setSupportZoom(true)
                            builtInZoomControls = true
                            displayZoomControls = false
                        }
                        if (p.serverUrl.isNotBlank()) {
                            loadUrl(p.serverUrl)
                        }
                    }
                },
                update = { webView ->
                    // Reload when prefs change and WebView is already created
                    if (p.serverUrl.isNotBlank() && webView.url == null) {
                        webView.loadUrl(p.serverUrl)
                    }
                }
            )
        }

        // Offline banner
        if (isOffline) {
            Text(
                text = "Offline — cached version",
                modifier = Modifier
                    .align(Alignment.TopCenter)
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.errorContainer)
                    .padding(horizontal = 16.dp, vertical = 6.dp),
                color = MaterialTheme.colorScheme.onErrorContainer,
                style = MaterialTheme.typography.labelMedium,
            )
        }
    }
}
