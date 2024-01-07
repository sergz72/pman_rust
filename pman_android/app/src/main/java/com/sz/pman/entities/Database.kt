package com.sz.pman.entities

import android.net.Uri
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.runtime.toMutableStateList
import androidx.compose.runtime.toMutableStateMap
import com.sz.pman.KeyFile
import uniffi.pman_lib.DatabaseEntity
import uniffi.pman_lib.PmanException
import uniffi.pman_lib.modifyEntity
import java.security.MessageDigest

data class DBGroup(val id: UInt, val name: String, val items: UInt)

data class DBEntity(val id: UInt, val entity: DatabaseEntity?) {
    var name = mutableStateOf(entity?.getName() ?: "")
    var showProperties = mutableStateOf(false)
    var propertyNames = mapOf<String, UInt>()
    var propertyFields = mutableStateMapOf<Int, Pair<MutableState<String>, StringEntityField>>()
    val userNameField = UIntEntityField(entity) { entity -> entity.getUserId(0U) }
    val groupField = UIntEntityField(entity) { entity -> entity.getGroupId(0U) }
    val passwordField = StringEntityField(entity) { entity -> entity.getPassword(0U) }
    val urlField = StringEntityField(entity) { entity -> entity.getUrl(0U) ?: "" }

    private var nextNewPropertyID = -1

    constructor(users: Map<UInt, String>, groups: Map<UInt, String>) : this(0U, null) {
        showProperties.value = true
        userNameField.selectFirst(users)
        groupField.selectFirst(groups)
        passwordField.editMode.value = true
        urlField.editMode.value = true
    }

    fun toggleShowProperties() {
        showProperties.value = !showProperties.value
        if (showProperties.value) {
            getPropertyNames()
        }
    }

    fun getPropertyNames() {
        propertyNames = entity?.getPropertyNames(0U) ?: mapOf()
        propertyFields = propertyNames.map {
            it.value.toInt() to
                    Pair(
                        mutableStateOf(it.key),
                        StringEntityField(entity) { entity ->
                            entity.getPropertyValue(
                                0U,
                                it.value
                            )
                        })
        }.toMutableStateMap()
    }

    fun newProperty() {
        propertyFields[nextNewPropertyID--] = Pair(mutableStateOf(""), StringEntityField())
    }

    fun reset() {
        showProperties.value = false
        userNameField.editMode.value = false
        groupField.editMode.value = false
        passwordField.editMode.value = false
        urlField.editMode.value = false
    }

    fun buildProperties(): Map<String, String> {
        return propertyFields.filter {
            it.value.first.value != "" && it.value.second.value.value != "" && it.key < 0
        }
            .map { it.value.first.value to it.value.second.value.value }.toMap()
    }

    fun buildModifiedProperties(): Map<UInt, String> {
        return propertyFields.filter {
            it.value.second.buildValue() != null && it.key > 0
        }
            .map { it.key.toUInt() to it.value.second.buildValue()!! }.toMap()
    }
}

data class StringEntityField(val entity: DatabaseEntity?, val getter: (DatabaseEntity) -> String) {
    private var initialValue = ""
    var value = mutableStateOf("")
    var editMode = mutableStateOf(false)

    fun buildValue(): String? {
        return if (editMode.value && initialValue != value.value) {
            value.value
        } else {
            null
        }
    }

    constructor() : this(null, { _ -> "" }) {
        editMode.value = true
    }

    fun getValue() {
        value.value = if (entity != null) {
            getter.invoke(entity)
        } else {
            ""
        }
        initialValue = value.value
    }
}

data class UIntEntityField(val entity: DatabaseEntity?, val getter: (DatabaseEntity) -> UInt) {
    private var initialValue = 0U
    var value = 0U
    var editMode = mutableStateOf(false)

    fun buildValue(): UInt? {
        return if (editMode.value && initialValue != value) {
            value
        } else {
            null
        }
    }

    constructor() : this(null, { _ -> 1U }) {
        editMode.value = true
    }

    fun getValue() {
        value = if (entity != null) {
            getter.invoke(entity)
        } else {
            0U
        }
        initialValue = value
    }

    fun selectFirst(list: Map<UInt, String>) {
        editMode.value = true
        value = list.keys.firstOrNull() ?: 0U
        initialValue = UInt.MAX_VALUE
    }
}

data class Database(
    val name: String, val uri: Uri, val errorMessage: String, val id: ULong,
    var keyFile: MutableState<KeyFile>, var groups: SnapshotStateList<DBGroup>,
    var entities: SnapshotStateList<DBEntity>
) {
    companion object {
        fun newDatabase(name: String, uri: Uri, data: ByteArray): Database {
            var dbId = 0UL
            var message = ""
            try {
                dbId = uniffi.pman_lib.prepare(data, name)
            } catch (e: PmanException) {
                message = e.toString()
            }
            return Database(
                name, uri, message, dbId, mutableStateOf(KeyFile()), mutableStateListOf(),
                mutableStateListOf()
            )
        }

        fun newDatabase(name: String, uri: Uri, keyFile: KeyFile, data: ByteArray): Database {
            var dbId = 0UL
            var message = ""
            try {
                dbId = uniffi.pman_lib.prepare(data, name)
            } catch (e: PmanException) {
                message = e.toString()
            }
            return Database(
                name, uri, message, dbId, mutableStateOf(keyFile), mutableStateListOf(),
                mutableStateListOf()
            )
        }
    }

    var isOpened = mutableStateOf(false)
    var isModified = mutableStateOf(false)
    var selectedGroup: MutableState<DBGroup?> = mutableStateOf(null)
    var selectedEntity: MutableState<DBEntity?> = mutableStateOf(null)
    var users = mapOf<UInt, String>()

    fun selectGroup(dbGroup: DBGroup?): String {
        selectedGroup.value = dbGroup
        selectedEntity.value = null
        return try {
            entities = if (dbGroup != null) {
                uniffi.pman_lib.getEntities(id, dbGroup.id).map { DBEntity(it.key, it.value) }
                    .toMutableStateList()
            } else {
                mutableStateListOf()
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
            uniffi.pman_lib.preOpen(
                id, md.digest(passwordBytes), md.digest(password2Bytes),
                keyFile.value.data
            )
            uniffi.pman_lib.open(id)
            isOpened.value = true
            val dbGroups = uniffi.pman_lib.getGroups(id)
            groups = dbGroups.map { DBGroup(it.getId(), it.getName(), it.getEntitiesCount()) }
                .sortedBy { it.name }.toMutableStateList()
            users = uniffi.pman_lib.getUsers(id)
        } catch (e: PmanException) {
            return e.toString()
        }
        return ""
    }

    fun saveEntity(entity: DBEntity) {
        if (entity.id > 0U) {
            this.modifyEntity(entity)
        } else {
            uniffi.pman_lib.addEntity(
                id, entity.name.value, entity.groupField.value,
                entity.userNameField.value, entity.passwordField.value.value,
                if (entity.urlField.value.value.isEmpty()) {
                    null
                } else {
                    entity.urlField.value.value
                },
                entity.buildProperties()
            )
            val dbGroups = uniffi.pman_lib.getGroups(id)
            groups = dbGroups.map { DBGroup(it.getId(), it.getName(), it.getEntitiesCount()) }
                .sortedBy { it.name }.toMutableStateList()
            selectedGroup.value = null
        }
        entities = uniffi.pman_lib.getEntities(id, selectedGroup.value!!.id)
            .map { DBEntity(it.key, it.value) }.toMutableStateList()
        selectedEntity.value = null
        isModified.value = true
    }

    private fun modifyEntity(entity: DBEntity) {
        val newGroupId = entity.groupField.buildValue()
        val newUserId = entity.userNameField.buildValue()
        val newPassword = entity.passwordField.buildValue()
        val url = entity.urlField.buildValue()
        val changeUrl = url != null
        val newUrl = if (changeUrl && url!!.isNotEmpty()) {
            url
        } else {
            null
        }
        val newProperties = entity.buildProperties()
        val modifiedProperties = entity.buildModifiedProperties()
        modifyEntity(
            id, entity.id, newGroupId, newUserId, newPassword, newUrl,
            changeUrl, newProperties, modifiedProperties
        )
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
