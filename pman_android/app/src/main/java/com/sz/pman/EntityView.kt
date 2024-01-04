package com.sz.pman

import android.net.Uri
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.Button
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sz.pman.entities.DBEntity
import com.sz.pman.entities.Database
import com.sz.pman.entities.StringEntityField
import com.sz.pman.entities.UIntEntityField
import com.sz.pman.ui.theme.PmanTheme

@Composable
fun EntityView(entityToEdit: MutableState<DBEntity?>, database: Database) {
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Name", modifier = Modifier.width(60.dp))
            BasicTextField(
                value = entityToEdit.value!!.name,
                readOnly = entityToEdit.value!!.entity != null,
                onValueChange = { },
                modifier = Modifier
                    .fillMaxWidth()
                    .then(Modifier.border(1.dp, Color.LightGray))
                    .then(Modifier.height(40.dp)),
            )
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Group", modifier = Modifier.width(60.dp))
            UIntFieldEdit(
                entityToEdit.value!!.groupField,
                database.groups.map { it.id to it.name }.toMap()
            )
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("User", modifier = Modifier.width(60.dp))
            UIntFieldEdit(entityToEdit.value!!.userNameField, database.users)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("URL", modifier = Modifier.width(60.dp))
            StringFieldEdit(entityToEdit.value!!.urlField)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Properties", modifier = Modifier.weight(1f))
            if (entityToEdit.value!!.showProperties.value) {
                Button(onClick = { }) {
                    Text("+")
                }
            } else {
                Button(onClick = { entityToEdit.value!!.toggleShowProperties() }) {
                    Text("Show")
                }
            }
        }
        if (entityToEdit.value!!.showProperties.value) {
            Column {
                entityToEdit.value!!.propertyNames.forEach {
                    Row {
                        Text(it.key)
                        StringFieldEdit(entityToEdit.value!!.propertyFields[it.value]!!)
                    }
                }
            }
        }
        Row {
            Button(onClick = {
                entityToEdit.value?.reset()
                entityToEdit.value = null
            }, modifier = Modifier.weight(0.5f)) {
                Text("Cancel")
            }
            Button(onClick = { }, modifier = Modifier.weight(0.5f)) {
                Text("Save")
            }
        }
    }
}

@Composable
fun StringFieldEdit(field: StringEntityField) {
    if (field.editMode.value) {
        BasicTextField(
            value = field.value.value,
            onValueChange = { field.value.value = it },
            modifier = Modifier
                .fillMaxWidth()
                .then(Modifier.border(1.dp, Color.LightGray))
                .then(Modifier.height(40.dp)),
            textStyle = LocalTextStyle.current.copy(fontSize = 28.sp)
        )
    } else {
        Button(onClick = {
            field.getValue()
            field.editMode.value = true
        }, modifier = Modifier.fillMaxWidth()) {
            Text("Edit")
        }
    }
}

@Composable
fun UIntFieldEdit(field: UIntEntityField, list: Map<UInt, String>) {
    var expanded by remember { mutableStateOf(false) }
    var selectedItemText by remember { mutableStateOf("") }

    if (field.editMode.value) {
        Column {
            if (expanded) {
                list.forEach {
                    Text(it.value,
                        Modifier
                            .clickable {
                                selectedItemText = it.value
                                field.value = it.key
                                expanded = false
                            }
                            .then(Modifier.fillMaxWidth()))
                }
            } else {
                Text(
                    selectedItemText, modifier = Modifier
                        .fillMaxWidth()
                        .then(Modifier.clickable {
                            expanded = true
                        })
                )
            }
        }
    } else {
        Button(onClick = {
            field.getValue()
            selectedItemText = list[field.value] ?: "Unknown"
            field.editMode.value = true
        }, modifier = Modifier.fillMaxWidth()) {
            Text("Edit")
        }
    }
}

@Preview(showBackground = true)
@Composable
fun EntityViewPreview() {
    val keyFile = remember { mutableStateOf(KeyFile()) }
    val entityToEdit = remember { mutableStateOf(DBEntity(0U, null) as DBEntity?) }

    PmanTheme {
        EntityView(
            entityToEdit,
            Database("test", Uri.EMPTY, "", 1UL, keyFile, listOf(), listOf())
        )
    }
}

@Preview(showBackground = true)
@Composable
fun UIntFieldEditPreview() {
    PmanTheme {
        UIntFieldEdit(UIntEntityField(), mapOf(1U to "ee", 2U to "dd", 3U to "ww"))
    }
}