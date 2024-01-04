package com.sz.pman.entities

import android.net.Uri
import android.provider.Contacts.Intents.UI
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import com.sz.pman.KeyFile
import uniffi.pman_lib.DatabaseEntity
import uniffi.pman_lib.PmanException
import java.security.MessageDigest

data class DBGroup(val id: UInt, val name: String, val items: UInt)

data class DBEntity(val id: UInt, val entity: DatabaseEntity?) {
    val name: String = entity?.getName() ?: ""
    var showProperties = mutableStateOf(false)
    var propertyNames = mapOf<String, UInt>()
    var propertyFields = mapOf<UInt, StringEntityField>()
    val userNameField = UIntEntityField(entity) { entity -> entity.getUserId(0U) }
    val groupField = UIntEntityField(entity) { entity -> entity.getGroupId(0U) }
    val passwordField = StringEntityField(entity) { entity -> entity.getPassword(0U)}
    val urlField = StringEntityField(entity) { entity -> entity.getUrl(0U) ?: ""}

    fun toggleShowProperties() {
        showProperties.value = !showProperties.value
        if (showProperties.value) {
            getPropertyNames()
        }
    }
    fun getPropertyNames() {
        propertyNames = entity?.getPropertyNames(0U) ?: mapOf()
        propertyFields = propertyNames.map { it.value to
                StringEntityField(entity) {entity -> entity.getPropertyValue(0U, it.value)}
        }.toMap()
    }

    fun reset() {
        showProperties.value = false
        userNameField.editMode.value = false
        groupField.editMode.value = false
        passwordField.editMode.value = false
        urlField.editMode.value = false
    }
}

data class StringEntityField(val entity: DatabaseEntity?, val getter: (DatabaseEntity) -> String) {
    var initialValue = ""
    var value = mutableStateOf("")
    var editMode = mutableStateOf(false)
    fun getValue() {
        value.value = if (entity != null) {getter.invoke(entity)} else {""}
        initialValue = value.value
    }
}

data class UIntEntityField(val entity: DatabaseEntity?, val getter: (DatabaseEntity) -> UInt) {
    var initialValue = 0U
    var value = 0U
    var editMode = mutableStateOf(false)

    constructor(): this(null, {_ -> 1U}) {
        editMode.value = true
    }

    fun getValue() {
        value = if (entity != null) {getter.invoke(entity)} else {0U}
        initialValue = value
    }
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
    var users = mapOf<UInt, String>()

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
            users = uniffi.pman_lib.getUsers(id)
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
