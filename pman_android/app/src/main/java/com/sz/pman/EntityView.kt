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
fun EntityView(entityToEdit: DBEntity, database: Database) {
    var propertiesShown by remember { mutableStateOf(false) }

    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Name", modifier = Modifier.width(60.dp))
            BasicTextField(
                value = entityToEdit.name,
                readOnly = entityToEdit.entity != null,
                onValueChange = { },
                modifier = Modifier
                    .fillMaxWidth()
                    .then(Modifier.border(1.dp, Color.LightGray))
                    .then(Modifier.height(40.dp)),
            )
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Group", modifier = Modifier.width(60.dp))
            UIntFieldEdit(entityToEdit.groupField, database.groups.map { it.id to it.name }.toMap())
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("User", modifier = Modifier.width(60.dp))
            UIntFieldEdit(entityToEdit.userNameField, database.users)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("URL", modifier = Modifier.width(60.dp))
            StringFieldEdit(entityToEdit.urlField)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Properties", modifier = Modifier.weight(1f))
            Button(onClick = { }) {
                Text("Show")
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
        Button(onClick = { field.editMode.value = true }, modifier = Modifier.fillMaxWidth()) {
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
                Text(selectedItemText, modifier = Modifier
                    .fillMaxWidth()
                    .then(Modifier.clickable {
                        expanded = true
                    }))
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

    PmanTheme {
        EntityView(
            DBEntity(0U, null),
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