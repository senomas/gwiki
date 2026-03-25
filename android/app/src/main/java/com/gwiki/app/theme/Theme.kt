package com.gwiki.app.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Matches gwiki web: bg #0b0e11, accent sky-500 (#0ea5e9), text slate-100 (#f1f5f9)
private val GwikiDarkColors = darkColorScheme(
    primary = Color(0xFF0EA5E9),       // sky-500
    onPrimary = Color(0xFF0B0E11),
    primaryContainer = Color(0xFF0369A1), // sky-700
    onPrimaryContainer = Color(0xFFE0F2FE),
    background = Color(0xFF0B0E11),
    onBackground = Color(0xFFF1F5F9),  // slate-100
    surface = Color(0xFF131820),
    onSurface = Color(0xFFF1F5F9),
    surfaceVariant = Color(0xFF1E2530),
    onSurfaceVariant = Color(0xFF94A3B8), // slate-400
    outline = Color(0xFF334155),        // slate-700
    error = Color(0xFFF87171),          // red-400
)

@Composable
fun GwikiTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = GwikiDarkColors,
        content = content,
    )
}
