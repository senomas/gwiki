package com.gwiki.app.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "gwiki_prefs")

data class GwikiPrefs(
    val serverUrl: String = "",
    val username: String = "",
    val password: String = "",
    val apiKey: String = "",
    val cacheMb: Int = 50,
)

class Prefs(private val context: Context) {

    companion object {
        private val KEY_SERVER_URL = stringPreferencesKey("server_url")
        private val KEY_USERNAME = stringPreferencesKey("username")
        private val KEY_PASSWORD = stringPreferencesKey("password")
        private val KEY_API_KEY = stringPreferencesKey("api_key")
        private val KEY_CACHE_MB = intPreferencesKey("cache_mb")
    }

    val flow: Flow<GwikiPrefs> = context.dataStore.data.map { p ->
        GwikiPrefs(
            serverUrl = p[KEY_SERVER_URL] ?: "",
            username = p[KEY_USERNAME] ?: "",
            password = p[KEY_PASSWORD] ?: "",
            apiKey = p[KEY_API_KEY] ?: "",
            cacheMb = p[KEY_CACHE_MB] ?: 50,
        )
    }

    suspend fun read(): GwikiPrefs = flow.first()

    suspend fun save(prefs: GwikiPrefs) {
        context.dataStore.edit { p ->
            p[KEY_SERVER_URL] = prefs.serverUrl
            p[KEY_USERNAME] = prefs.username
            p[KEY_PASSWORD] = prefs.password
            p[KEY_API_KEY] = prefs.apiKey
            p[KEY_CACHE_MB] = prefs.cacheMb
        }
    }
}
