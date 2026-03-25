package com.gwiki.app.data

import com.google.gson.annotations.SerializedName
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.Path
import java.util.concurrent.TimeUnit

data class NoteResponse(
    @SerializedName("path") val path: String,
    @SerializedName("content") val content: String,
    @SerializedName("title") val title: String,
)

data class SaveNoteRequest(
    @SerializedName("path") val path: String,
    @SerializedName("content") val content: String,
)

data class SaveNoteResponse(
    @SerializedName("path") val path: String,
    @SerializedName("created") val created: Boolean,
    @SerializedName("message") val message: String,
)

interface NoteApiService {
    @GET("api/notes/{path}")
    suspend fun getNote(
        @Path("path", encoded = true) path: String,
        @Header("X-API-Key") apiKey: String,
    ): NoteResponse

    @POST("api/notes")
    suspend fun saveNote(
        @Header("X-API-Key") apiKey: String,
        @Body body: SaveNoteRequest,
    ): SaveNoteResponse
}

fun buildNoteApi(baseUrl: String): NoteApiService {
    val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    val normalizedBase = if (baseUrl.endsWith("/")) baseUrl else "$baseUrl/"
    return Retrofit.Builder()
        .baseUrl(normalizedBase)
        .client(client)
        .addConverterFactory(GsonConverterFactory.create())
        .build()
        .create(NoteApiService::class.java)
}
