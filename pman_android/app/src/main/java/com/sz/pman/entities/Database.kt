package com.sz.pman.entities

import uniffi.pman_lib.PmanException
import java.security.MessageDigest

data class Database(val name: String, val errorMessage: String, val id: ULong) {
    companion object {
        fun NewDatabase(name: String, data: ByteArray): Database {
            var dbId = 0UL
            var message = ""
            try {
                dbId = uniffi.pman_lib.prepare(data, name)
            } catch (e: PmanException) {
                message = e.toString()
            }
            return Database(name, message, dbId)
        }
    }

    var isOpened = false

    fun open(password: String, password2: String, keyFileContents: ByteArray?): String {
        try {
            val md = MessageDigest.getInstance("SHA-256")
            val passwordBytes = password.toByteArray(Charsets.UTF_8)
            val password2Bytes = password2.toByteArray(Charsets.UTF_8)
            uniffi.pman_lib.preOpen(id, md.digest(passwordBytes), md.digest(password2Bytes),
                keyFileContents)
            uniffi.pman_lib.open(id)
        } catch (e: PmanException) {
            return e.toString()
        }
        return ""
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Database

        return name == other.name
    }

    override fun hashCode(): Int {
        return name.hashCode()
    }
}
