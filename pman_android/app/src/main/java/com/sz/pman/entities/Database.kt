package com.sz.pman.entities

import android.net.Uri

data class Database(val name: String, val data: ByteArray) {
    var isOpened = false

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
