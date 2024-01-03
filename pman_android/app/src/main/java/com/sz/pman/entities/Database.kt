package com.sz.pman.entities

import android.net.Uri
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import com.sz.pman.KeyFile
import uniffi.pman_lib.DatabaseEntity
import uniffi.pman_lib.PmanException
import java.security.MessageDigest

data class DBGroup(val id: UInt, val name: String, val items: UInt)

data class DBEntity(val id: UInt, val entity: DatabaseEntity) {
    val name: String = entity.getName()
}

data class Database(val name: String, val uri: Uri, val errorMessage: String, val id: ULong,
                    var keyFile: MutableState<KeyFile>, var groups: List<DBGroup>, var entities: List<DBEntity>) {
    companion object {
        fun newDatabase(name: String, uri: Uri, data: ByteArray): Database {
            var dbId = 0UL
            var message = ""
            try {
                dbId = uniffi.pman_lib.prepare(data, name)
            } catch (e: PmanException) {
                message = e.toString()
            }
            return Database(name, uri, message, dbId, mutableStateOf(KeyFile()), listOf(), listOf())
        }

        fun newDatabase(name: String, uri: Uri, keyFile: KeyFile, data: ByteArray): Database {
            var dbId = 0UL
            var message = ""
            try {
                dbId = uniffi.pman_lib.prepare(data, name)
            } catch (e: PmanException) {
                message = e.toString()
            }
            return Database(name, uri, message, dbId, mutableStateOf(keyFile), listOf(), listOf())
        }
    }

    var isOpened = mutableStateOf(false)
    var selectedGroup: MutableState<DBGroup?> = mutableStateOf(null)
    var selectedEntity: MutableState<DBEntity?> = mutableStateOf(null)

    fun selectGroup(dbGroup: DBGroup?): String {
        selectedGroup.value = dbGroup
        selectedEntity.value = null
        return try {
            entities = if (dbGroup != null) {
                uniffi.pman_lib.getEntities(id, dbGroup.id).map { DBEntity(it.key, it.value) }
            } else {
                listOf()
            }
            ""
        } catch (e: PmanException) {
            e.toString()
        }
    }

    fun open(password: String, password2: String): String {
        try {
            val md = MessageDigest.getInstance("SHA-256")
            val passwordBytes = password.toByteArray(Charsets.UTF_8)
            val password2Bytes = password2.toByteArray(Charsets.UTF_8)
            uniffi.pman_lib.preOpen(id, md.digest(passwordBytes), md.digest(password2Bytes),
                keyFile.value.data)
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
