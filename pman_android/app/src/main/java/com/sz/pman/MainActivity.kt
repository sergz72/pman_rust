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
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Divider
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.toMutableStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.sp
import androidx.documentfile.provider.DocumentFile
import com.sz.pman.entities.Database
import java.io.FileInputStream
import java.lang.Exception

const val PICK_FILE = 1
const val PICK_KEY = 2
const val REMOVE_DATABASE = 3

class MainActivity : ComponentActivity(), ActivityResultCallback<ActivityResult> {

    private var mActivityResultLauncher: ActivityResultLauncher<Intent>? = null
    private lateinit var mDatabases: MutableList<Database>
    private var openFileCode = -1
    private var selectedDatabase = mutableStateOf(null as Database?)

    private lateinit var mSharedPreferences: SharedPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        uniffi.pman_lib.libInit()

        mSharedPreferences = getSharedPreferences("pman", Context.MODE_PRIVATE)
        loadDatabases()

        mActivityResultLauncher =
            registerForActivityResult(ActivityResultContracts.StartActivityForResult(), this)

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
                    MainView(mDatabases, selectedDatabase) { code -> mainViewAction(code) }
                }
            }
        }
    }

    private fun loadDatabases() {
        mDatabases = mSharedPreferences.getStringSet("databases", setOf())!!
            .mapNotNull { toDatabase(it) }
            .toMutableStateList()
    }

    private fun toDatabase(it: String): Database? {
        val params = it.split('|')
        return if (params.size == 3) {
            val mainFileName = params[0]
            val mainFileUri = Uri.parse(params[1])
            try {
                val mainFileContents = readFile(mainFileUri)
                val keyFileUri = if (params[2].isNotEmpty()) {
                    Uri.parse(params[2])
                } else {
                    Uri.EMPTY
                }
                val keyFileContents = if (keyFileUri != Uri.EMPTY) {
                    try {
                        readFile(keyFileUri)
                    } catch (e: Exception) {
                        null
                    }
                } else {
                    null
                }
                val keyFileName = if (keyFileContents != null) {
                    val keyDocument = DocumentFile.fromSingleUri(this, keyFileUri)
                    keyDocument?.name!!
                } else {
                    ""
                }
                Database.newDatabase(
                    mainFileName,
                    mainFileUri,
                    KeyFile(keyFileName, keyFileUri, keyFileContents),
                    mainFileContents
                )
            } catch (e: Exception) {
                Database(
                    mainFileName,
                    mainFileUri,
                    e.message!!,
                    0UL,
                    mutableStateOf(KeyFile()),
                    listOf(),
                    listOf()
                )
            }
        } else {
            null
        }
    }

    private fun mainViewAction(code: Int) {
        if (code == REMOVE_DATABASE) {
            uniffi.pman_lib.remove(selectedDatabase.value!!.id)
            mDatabases.remove(selectedDatabase.value)
            saveDatabases()
            selectedDatabase.value = null
            return
        }

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
                contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
                val bytes = readFile(uri)
                val document = DocumentFile.fromSingleUri(this, uri)
                if (openFileCode == PICK_FILE) {
                    mDatabases.add(Database.newDatabase(document?.name!!, uri, bytes))
                } else {
                    selectedDatabase.value!!.keyFile.value = KeyFile(document?.name!!, uri, bytes)
                }
                saveDatabases()
            }
        }
    }

    private fun saveDatabases() {
        val databaseList = mDatabases.map { it.name + "|" + it.uri.toString() + "|" + it.keyFile.value.uri }.toSet()
        val editor = mSharedPreferences.edit()
        editor.putStringSet("databases", databaseList)
        editor.apply()
    }
}

data class Alert(
    var show: MutableState<Boolean>, val title: String, val message: String, val confirmButtonText: String,
    val handler: () -> Unit
) {
    constructor(): this(mutableStateOf(false), "", "", "", {})
}

@Composable
fun MainView(
    databases: List<Database>, selectedDatabase: MutableState<Database?>,
    action: (Int) -> Unit
) {
    val alert = remember { mutableStateOf(Alert()) }

    if (alert.value.show.value) {
        AlertDialog(
            onDismissRequest = { alert.value.show.value = false },
            confirmButton = {
                Button(onClick = {
                    alert.value.handler.invoke()
                    alert.value.show.value = false
                }) {
                    Text(alert.value.confirmButtonText)
                }
            },
            title = { Text(alert.value.title) },
            text = { Text(alert.value.message) },
            dismissButton = {
                Button(onClick = {
                    alert.value.show.value = false
                }) {
                    Text("Cancel")
                }
            })
    }
    Column {
        HeaderView("Databases", Color.Cyan, true) { action(PICK_FILE) }
        Column {
            databases.forEach { database ->
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .background(
                            if (database == selectedDatabase.value)
                                Color.Green else Color.White
                        )
                        .selectable(
                            selected = database == selectedDatabase.value,
                            onClick = {
                                if (database != selectedDatabase.value) {
                                    selectedDatabase.value = database
                                }
                            }
                        ),
                ) {
                    Text(
                        text = database.name,
                        modifier = Modifier.weight(1f),
                        fontSize = 20.sp
                    )
                    if (database == selectedDatabase.value) {
                        Button(onClick = {
                            alert.value = Alert(
                                mutableStateOf(true),
                                "Remove database", "Remove database?",
                                "Remove"
                            ) { action(REMOVE_DATABASE) }
                        }) {
                            Text("Remove")
                        }
                    }
                }
            }
        }
        Divider()
        PasswordOrMessageView(selectedDatabase.value, action)
    }
}

@Composable
fun HeaderView(title: String, color: Color, buttonEnabled: Boolean, addHandler: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.background(color)
    ) {
        Text(text = title)
        Spacer(Modifier.weight(1f))
        Button(onClick = addHandler, enabled = buttonEnabled) {
            Text("+")
        }
    }
}

@Composable
fun PasswordOrMessageView(selectedDatabase: Database?, openFile: (Int) -> Unit) {
    if (selectedDatabase == null) {
        Spacer(modifier = Modifier.fillMaxHeight())
    } else if (selectedDatabase.errorMessage != "") {
        Text(selectedDatabase.errorMessage, modifier = Modifier.fillMaxHeight(), color = Color.Red)
    } else if (selectedDatabase.isOpened.value) {
        DatabaseView(selectedDatabase)
    } else {
        PasswordView(selectedDatabase, openFile)
    }
}

@Preview(showBackground = true)
@Composable
fun MainViewPreview() {
    var keyFile = remember { mutableStateOf(KeyFile()) }
    var selectedDatabase = remember { mutableStateOf(null as Database?) }

    PmanTheme {
        MainView(
            listOf(
                Database("test", Uri.EMPTY, "", 1UL, keyFile, listOf(), listOf()),
                Database("test2", Uri.EMPTY, "test error", 2UL, keyFile, listOf(), listOf())
            ), selectedDatabase
        ) {}
    }
}