package com.gwiki.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.gwiki.app.data.Prefs
import com.gwiki.app.data.buildNoteApi
import com.gwiki.app.theme.GwikiTheme
import com.gwiki.app.ui.EditorScreen
import com.gwiki.app.ui.SettingsScreen
import com.gwiki.app.ui.WikiWebViewScreen
import java.net.URLDecoder
import java.net.URLEncoder

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val prefs = Prefs(applicationContext)

        setContent {
            GwikiTheme {
                val gwikiPrefs by prefs.flow.collectAsState(initial = null)
                val navController = rememberNavController()

                // Decide start destination once prefs are loaded
                val startDest = if (gwikiPrefs?.serverUrl.isNullOrBlank()) "settings" else "wiki"

                NavHost(navController = navController, startDestination = startDest) {
                    composable("wiki") {
                        WikiWebViewScreen(
                            prefs = prefs,
                            onEditUrl = { editUrl ->
                                // Extract note path from the edit URL and navigate to editor
                                val path = extractNotePath(editUrl)
                                if (path.isNotBlank()) {
                                    val encoded = URLEncoder.encode(path, "UTF-8")
                                    navController.navigate("editor/$encoded")
                                }
                            }
                        )
                    }

                    composable("settings") {
                        SettingsScreen(
                            prefs = prefs,
                            onBack = if (gwikiPrefs?.serverUrl.isNullOrBlank()) null
                            else ({ navController.popBackStack() })
                        )
                    }

                    composable(
                        route = "editor/{path}",
                        arguments = listOf(navArgument("path") { type = NavType.StringType })
                    ) { backStackEntry ->
                        val encodedPath = backStackEntry.arguments?.getString("path") ?: ""
                        val notePath = URLDecoder.decode(encodedPath, "UTF-8")
                        val p = gwikiPrefs
                        if (p != null) {
                            val api = remember(p.serverUrl) { buildNoteApi(p.serverUrl) }
                            EditorScreen(
                                notePath = notePath,
                                prefs = p,
                                api = api,
                                onSaved = { navController.popBackStack() },
                                onBack = { navController.popBackStack() },
                            )
                        }
                    }
                }
            }
        }
    }

    /**
     * Extracts the note path from an edit URL.
     * e.g. http://server/notes/foo/bar/edit -> notes/foo/bar.md
     *      http://server/notes/new          -> (empty, handled by web)
     */
    private fun extractNotePath(url: String): String {
        return try {
            val path = java.net.URI(url).path
            when {
                path.endsWith("/edit") -> {
                    val withoutEdit = path.removeSuffix("/edit").trimStart('/')
                    // withoutEdit is like "notes/foo/bar" → add .md
                    if (!withoutEdit.endsWith(".md")) "$withoutEdit.md" else withoutEdit
                }
                else -> ""
            }
        } catch (e: Exception) {
            ""
        }
    }
}
