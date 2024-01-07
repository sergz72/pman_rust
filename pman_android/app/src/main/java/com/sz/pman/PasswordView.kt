package com.sz.pman

import android.net.Uri
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sz.pman.entities.DBEntity
import com.sz.pman.entities.DBGroup
import com.sz.pman.entities.Database
import com.sz.pman.ui.theme.PmanTheme

data class KeyFile(val name: String, val uri: Uri, val data: ByteArray?) {

    constructor(): this("", Uri.EMPTY, null)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as KeyFile

        return name == other.name
    }

    override fun hashCode(): Int {
        return name.hashCode()
    }
}

@Composable
fun PasswordView(
    selectedDatabase: Database, openFile: (Int) -> Unit
) {
    var password1 by remember { mutableStateOf("") }
    var password2 by remember { mutableStateOf("") }
    var errorMessage by remember { mutableStateOf("") }

    Column(modifier = Modifier.fillMaxHeight(), verticalArrangement = Arrangement.Center) {
        Text("First password", modifier = Modifier.width(150.dp))
        BasicTextField(
            value = password1,
            onValueChange = { password1 = it },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier
                .fillMaxWidth()
                .then(Modifier.border(1.dp, Color.LightGray))
                .then(Modifier.height(40.dp)),
            textStyle = LocalTextStyle.current.copy(fontSize = 28.sp)
        )
        Text("Second password", modifier = Modifier.width(150.dp))
        BasicTextField(
            value = password2,
            onValueChange = { password2 = it },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier
                .fillMaxWidth()
                .then(Modifier.border(1.dp, Color.LightGray))
                .then(Modifier.height(40.dp)),
            textStyle = LocalTextStyle.current.copy(fontSize = 28.sp)
        )
        Text("Key file", modifier = Modifier.width(150.dp))
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.height(50.dp)
        ) {
            Text(
                text = selectedDatabase.keyFile.value.name,
                modifier = Modifier
                    .weight(1f)
                    .then(Modifier.border(1.dp, Color.LightGray))
                    .then(Modifier.height(40.dp)),
                fontSize = 28.sp
            )
            Button(onClick = { openFile(PICK_KEY) }) {
                Text("Select")
            }
        }
        Button(
            onClick = {
                errorMessage = selectedDatabase.open(password1, password2)
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Open database")
        }
        Text(errorMessage, modifier = Modifier.fillMaxWidth(), color = Color.Red)
    }
}

@Preview(showBackground = true)
@Composable
fun PasswordViewPreview() {
    val keyFile = remember { mutableStateOf(KeyFile()) }
    val groups = remember { mutableStateListOf<DBGroup>() }
    val entities = remember { mutableStateListOf<DBEntity>() }

    PmanTheme {
        PasswordView(Database("test", Uri.EMPTY, "", 1UL, keyFile, groups, entities)) {}
    }
}