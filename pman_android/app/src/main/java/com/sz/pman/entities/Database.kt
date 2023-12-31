package com.sz.pman.entities

import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import uniffi.pman_lib.PmanException
import java.security.MessageDigest

data class DBGroup(val id: UInt, val name: String, val items: UInt)

data class Database(val name: String, val errorMessage: String, val id: ULong, var groups: List<DBGroup>) {
    companion object {
        fun newDatabase(name: String, data: ByteArray): Database {
            var dbId = 0UL
            var message = ""
            try {
                dbId = uniffi.pman_lib.prepare(data, name)
            } catch (e: PmanException) {
                message = e.toString()
            }
            return Database(name, message, dbId, listOf())
        }
    }

    var isOpened = mutableStateOf(false)
    var selectedGroup: MutableState<DBGroup?> = mutableStateOf(null)

    fun selectGroup(dbGroup: DBGroup) {
        selectedGroup.value = dbGroup
    }

    fun open(password: String, password2: String, keyFileContents: ByteArray?): String {
        try {
            val md = MessageDigest.getInstance("SHA-256")
            val passwordBytes = password.toByteArray(Charsets.UTF_8)
            val password2Bytes = password2.toByteArray(Charsets.UTF_8)
            uniffi.pman_lib.preOpen(id, md.digest(passwordBytes), md.digest(password2Bytes),
                keyFileContents)
            uniffi.pman_lib.open(id)
            isOpened.value = true
            val dbGroups = uniffi.pman_lib.getGroups(id)
            groups = dbGroups.map { DBGroup(it.getId(), it.getName(), it.getEntitiesCount()) }
                .sortedBy { it.name }
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
