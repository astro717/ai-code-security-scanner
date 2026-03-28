// clean.kt — Kotlin fixture with safe implementations.
// Used by kotlin-fixtures.vitest.ts to verify the Kotlin scanner emits zero findings.

package com.example.clean

import java.security.SecureRandom
import java.security.MessageDigest
import android.database.sqlite.SQLiteDatabase
import java.io.File

class SafeRepository(private val db: SQLiteDatabase) {

    // Safe: credential loaded from environment / config, not hardcoded
    private val baseUrl = "https://api.example.com"

    // Safe: SecureRandom for cryptographically strong randomness
    fun generateSessionToken(): ByteArray {
        val sr = SecureRandom()
        val bytes = ByteArray(32)
        sr.nextBytes(bytes)
        return bytes
    }

    // Safe: SHA-256 for hashing
    fun hashData(data: String): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(data.toByteArray())
    }

    // Safe: parameterised query — no injection possible
    fun getOrdersByUser(userId: String): android.database.Cursor {
        return db.rawQuery("SELECT * FROM orders WHERE user_id = ?", arrayOf(userId))
    }

    // Safe: path is validated against a known base directory
    fun readUserFile(baseDir: String, fileName: String): String {
        val base = File(baseDir).canonicalPath
        val target = File(baseDir, fileName).canonicalPath
        require(target.startsWith(base)) { "Path traversal detected" }
        return File(target).readText()
    }

    // Safe: non-sensitive display value in SharedPreferences
    fun saveDisplayName(prefs: android.content.SharedPreferences, name: String) {
        prefs.edit().putString("display_name", name).apply()
    }

    // Safe: batch query outside loop — no N+1
    fun processOrders(orderIds: List<String>): List<android.database.Cursor> {
        val placeholders = orderIds.joinToString(",") { "?" }
        val cursor = db.rawQuery(
            "SELECT * FROM orders WHERE id IN ($placeholders)",
            orderIds.toTypedArray()
        )
        return listOf(cursor)
    }
}
