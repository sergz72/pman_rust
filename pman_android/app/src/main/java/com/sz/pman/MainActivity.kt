package com.sz.pman

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.sz.pman.ui.theme.PmanTheme
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.ActivityResult
import androidx.activity.result.ActivityResultCallback
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.Button
import androidx.compose.material3.Divider
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.toMutableStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.documentfile.provider.DocumentFile
import com.sz.pman.entities.Database
import java.io.FileInputStream
import java.lang.Exception

const val PICK_FILE = 1
const val PICK_KEY = 2

class MainActivity : ComponentActivity(), ActivityResultCallback<ActivityResult> {

    private var mActivityResultLauncher: ActivityResultLauncher<Intent>? = null
    private lateinit var mDatabases: MutableList<Database>
    private var keyFile = mutableStateOf(KeyFile("", Uri.EMPTY, null))
    private var openFileCode = -1

    private lateinit var mSharedPreferences: SharedPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        uniffi.pman_lib.libInit()

        mSharedPreferences = getSharedPreferences("pman", Context.MODE_PRIVATE)
        loadDatabases()

        mActivityResultLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult(), this)

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
            }
        })

        setContent {
            PmanTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainView(mDatabases, keyFile) { code -> openFile(code) }
                }
            }
        }
    }

    private fun loadDatabases() {
        mDatabases =  mSharedPreferences.getStringSet("databases", setOf())!!
            .map { toDatabase(it) }
            .filterNotNull()
            .toMutableStateList()
    }

    private fun toDatabase(it: String): Database? {
        val params = it.split(':')
        return if (params.size == 2) {
            try {
                val mainFileContents = readFile(Uri.parse(params[0]))
                val keyFileUri = if (params[1].isNotEmpty()) {Uri.parse(params[1])} else {Uri.EMPTY}
                val keyFileContents = if (keyFileUri != Uri.EMPTY) {
                    try {
                        readFile(keyFileUri)
                    } catch (e: Exception) {
                        null
                    }
                } else {null}
                var keyFileName = if (keyFileContents != null) {params[1]} else {""}
                Database.newDatabase(params[0], KeyFile(keyFileName, keyFileUri, keyFileContents),
                    mainFileContents)
            } catch (e: Exception) {
                Database(params[0], e.message!!, 0UL, KeyFile(), listOf(), listOf())
            }
        } else {null}
    }

    private fun openFile(code: Int) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/*"
        }

        openFileCode = code

        mActivityResultLauncher!!.launch(intent)
    }

    private fun readFile(uri: Uri): ByteArray {
        val parcelFileDescriptor =
            contentResolver.openFileDescriptor(uri, "r")
        parcelFileDescriptor.use {
            val fileDescriptor = parcelFileDescriptor!!.fileDescriptor
            val stream = FileInputStream(fileDescriptor)
            return stream.readBytes()
        }
    }

    override fun onActivityResult(result: ActivityResult) {
        if (result.data == null) {
            return
        }
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.also { uri ->
                val bytes = readFile(uri)
                val document = DocumentFile.fromSingleUri(this, uri)
                if (openFileCode == PICK_FILE) {
                    mDatabases.add(Database.newDatabase(document?.name!!, bytes))
                } else {
                    keyFile.value = KeyFile(document?.name!!, uri, bytes)
                }
            }
        }
    }
}

@Composable
fun MainView(databases: List<Database>, keyFile: MutableState<KeyFile>, openFile: (Int) -> Unit) {
    var selectedDatabase by remember{mutableStateOf(null as Database?)}

    Column {
        HeaderView("Databases", Color.Cyan) { openFile(1) }
        Column {
            databases.forEach {database ->
                Text(
                    text = database.name,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            if (database == selectedDatabase)
                                Color.Green else Color.White
                        )
                        .selectable(
                            selected = database == selectedDatabase,
                            onClick = {
                                if (database != selectedDatabase) {
                                    selectedDatabase = database
                                }
                            }
                        )
                )
            }
        }
        Divider()
        PasswordOrMessageView(selectedDatabase, keyFile, openFile)
    }
}

@Composable
fun HeaderView(title: String, color: Color, addHandler: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.background(color)
    ) {
        Text(text = title)
        Spacer(Modifier.weight(1f))
        Button(onClick = addHandler) {
            Text("+")
        }
    }
}

@Composable
fun PasswordOrMessageView(selectedDatabase: Database?, keyFile: MutableState<KeyFile>,
                          openFile: (Int) -> Unit) {
    if (selectedDatabase == null) {
        Spacer(modifier = Modifier.fillMaxHeight())
    } else if (selectedDatabase.errorMessage != "") {
        Text(selectedDatabase.errorMessage, modifier = Modifier.fillMaxHeight(), color = Color.Red)
    } else if (selectedDatabase.isOpened.value) {
        DatabaseView(selectedDatabase)
    } else {
        PasswordView(selectedDatabase, keyFile, openFile)
    }
}

@Preview(showBackground = true)
@Composable
fun MainViewPreview() {
    var keyFile = remember { mutableStateOf(KeyFile()) }

    PmanTheme {
        MainView(listOf(
            Database("test", "", 1UL, KeyFile(), listOf(), listOf()),
            Database("test2", "test error", 2UL, KeyFile(), listOf(), listOf())
        ), keyFile) {}
    }
}