// vulnerable.kt — Kotlin fixture with intentional security vulnerabilities.
// Used by kotlin-fixtures.vitest.ts to verify the Kotlin scanner detects all covered types.

package com.example.vulnerable

import java.util.Random
import java.security.MessageDigest
import android.database.sqlite.SQLiteDatabase
import java.io.File

class VulnerableRepository(private val db: SQLiteDatabase) {

    // SECRET_HARDCODED — hardcoded API key in source
    val apiKey = "sk-liveabcdef1234567890secretkey"

    // SECRET_HARDCODED — hardcoded bearer token
    val secretToken = "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"

    // INSECURE_RANDOM — java.util.Random used for security-sensitive value
    fun generateSessionId(): Int {
        val rng = Random()
        return rng.nextInt()
    }

    // WEAK_CRYPTO — MD5 MessageDigest
    fun hashPassword(password: String): ByteArray {
        val md = MessageDigest.getInstance("MD5")
        return md.digest(password.toByteArray())
    }

    // WEAK_CRYPTO — SHA-1 MessageDigest
    fun legacyHash(data: String): ByteArray {
        val md = MessageDigest.getInstance("SHA-1")
        return md.digest(data.toByteArray())
    }

    // SQL_INJECTION — rawQuery with string concatenation
    fun getOrdersByUser(userId: String): android.database.Cursor {
        return db.rawQuery("SELECT * FROM orders WHERE user_id = " + userId, null)
    }

    // SQL_INJECTION — rawQuery with string interpolation
    fun getProductById(productId: String): android.database.Cursor {
        return db.rawQuery("SELECT * FROM products WHERE id = ${productId}", null)
    }

    // PATH_TRAVERSAL — File() with user-controlled path argument
    fun readUserFile(path: String): String {
        val file = File(path)
        return file.readText()
    }

    // INSECURE_SHARED_PREFS — storing password in SharedPreferences
    fun cacheCredentials(prefs: android.content.SharedPreferences, pass: String) {
        prefs.edit().putString("password", pass).apply()
    }

    // INSECURE_SHARED_PREFS — storing token in SharedPreferences
    fun cacheToken(prefs: android.content.SharedPreferences, tok: String) {
        prefs.edit().putString("token", tok).apply()
    }

    // PERFORMANCE_N_PLUS_ONE — database query inside a loop (deeply indented)
    fun processOrders(orderIds: List<String>) {
        orderIds.forEach { id ->
                db.rawQuery("SELECT * FROM orders WHERE id = ?", arrayOf(id))
        }
    }
}
