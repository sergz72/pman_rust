package com.sz.pman

import android.net.Uri
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.sz.pman.entities.DBEntity
import com.sz.pman.entities.Database
import com.sz.pman.entities.StringEntityField
import com.sz.pman.entities.UIntEntityField
import com.sz.pman.ui.theme.PmanTheme

@Composable
fun EntityView(entityToEdit: DBEntity, database: Database) {
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
            Text("User", modifier = Modifier.width(60.dp))
            UIntFieldEdit(entityToEdit.userNameField, database.users)
        }
    }
}

@Composable
fun StringFieldEdit(field: StringEntityField) {
    if (field.editMode.value) {
        BasicTextField(
            value = field.value,
            onValueChange = { },
            modifier = Modifier
                .fillMaxWidth()
                .then(Modifier.border(1.dp, Color.LightGray))
                .then(Modifier.height(40.dp)),
        )
    } else {
        Button(onClick = { field.editMode.value = true }, modifier = Modifier.fillMaxWidth()) {
            Text("Edit")
        }
    }
}

@Composable
fun UIntFieldEdit(field: UIntEntityField, list: Map<UInt, String>) {
    if (field.editMode.value) {
        DropdownMenu(expanded = false, onDismissRequest = { }, modifier = Modifier.fillMaxWidth()) {
            list.forEach { entry ->
                DropdownMenuItem(
                    text = { Text(entry.value) },
                    onClick = { field.value = entry.key }
                )
            }
        }
    } else {
        Button(onClick = { field.editMode.value = true }) {
            Text("Edit")
        }
    }
}

@Preview(showBackground = true)
@Composable
fun EntityViewPreview() {
    val keyFile = remember { mutableStateOf(KeyFile()) }

    PmanTheme {
        EntityView(DBEntity(0U, null),
            Database("test", Uri.EMPTY, "", 1UL, keyFile, listOf(), listOf()))
    }
}

@Preview(showBackground = true)
@Composable
fun UIntFieldEditPreview() {

    PmanTheme {
        UIntFieldEdit(UIntEntityField(), mapOf(1U to "ee"))
    }
}