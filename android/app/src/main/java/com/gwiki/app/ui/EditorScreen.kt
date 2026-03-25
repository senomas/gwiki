package com.gwiki.app.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import com.gwiki.app.data.GwikiPrefs
import com.gwiki.app.data.NoteApiService
import com.gwiki.app.data.SaveNoteRequest
import kotlinx.coroutines.launch
import java.time.LocalDate
import java.time.format.DateTimeFormatter

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditorScreen(
    notePath: String,
    prefs: GwikiPrefs,
    api: NoteApiService,
    onSaved: () -> Unit,
    onBack: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var content by remember { mutableStateOf(TextFieldValue("")) }
    var loading by remember { mutableStateOf(true) }
    var saving by remember { mutableStateOf(false) }

    // Load note content
    LaunchedEffect(notePath) {
        try {
            val resp = api.getNote(notePath, prefs.apiKey)
            content = TextFieldValue(resp.content)
        } catch (e: Exception) {
            snackbar.showSnackbar("Failed to load note: ${e.message}")
        } finally {
            loading = false
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(notePath.substringAfterLast("/").removeSuffix(".md")) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    TextButton(onClick = onBack) { Text("Discard") }
                    Button(
                        onClick = {
                            scope.launch {
                                saving = true
                                try {
                                    api.saveNote(prefs.apiKey, SaveNoteRequest(notePath, content.text))
                                    onSaved()
                                } catch (e: Exception) {
                                    snackbar.showSnackbar("Save failed: ${e.message}")
                                } finally {
                                    saving = false
                                }
                            }
                        },
                        enabled = !saving,
                        modifier = Modifier.padding(end = 8.dp),
                    ) { Text(if (saving) "Saving…" else "Save") }
                }
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            // Markdown toolbar
            MarkdownToolbar(
                onInsert = { snippet ->
                    val sel = content.selection
                    val text = content.text
                    val before = text.substring(0, sel.start)
                    val after = text.substring(sel.end)
                    val newText = before + snippet + after
                    val cursor = sel.start + snippet.length
                    content = TextFieldValue(newText, TextRange(cursor))
                }
            )
            OutlinedTextField(
                value = content,
                onValueChange = { content = it },
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                enabled = !loading,
                placeholder = { if (loading) Text("Loading…") },
            )
        }
    }
}

@Composable
private fun MarkdownToolbar(onInsert: (String) -> Unit) {
    val today = LocalDate.now().format(DateTimeFormatter.ofPattern("d MMM yyyy"))
    val buttons = listOf(
        "# H1" to "# ",
        "## H2" to "## ",
        "**B**" to "**text**",
        "_I_" to "_text_",
        "[ ]" to "- [ ] ",
        "`code`" to "`code`",
        "link" to "[text](url)",
        "!d" to today,
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 8.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        buttons.forEach { (label, snippet) ->
            FilterChip(
                selected = false,
                onClick = { onInsert(snippet) },
                label = { Text(label) },
            )
        }
    }
}
