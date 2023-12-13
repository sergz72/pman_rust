package com.sz.pman

import android.app.Activity
import android.content.Intent
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.documentfile.provider.DocumentFile
import com.sz.pman.entities.Database
import java.io.FileInputStream

class MainActivity : ComponentActivity(), ActivityResultCallback<ActivityResult> {
    private var mActivityResultLauncher: ActivityResultLauncher<Intent>? = null
    private val mDatabases: MutableList<Database> = mutableStateListOf()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        uniffi.pman_lib.libInit()

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
                    MainView(mDatabases) { openFile() }
                }
            }
        }
    }

    private fun openFile() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/*"
        }

        mActivityResultLauncher!!.launch(intent)
    }

    override fun onActivityResult(result: ActivityResult) {
        if (result.data == null) {
            return
        }
        val requestCode = result.data!!.getIntExtra("code", -1)
        if (requestCode == -1
            && result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.also { uri ->
                val parcelFileDescriptor =
                    contentResolver.openFileDescriptor(uri, "r")
                val fileDescriptor = parcelFileDescriptor!!.fileDescriptor
                val stream = FileInputStream(fileDescriptor)
                val bytes = stream.readBytes()
                val document = DocumentFile.fromSingleUri(this, uri)
                mDatabases.add(Database(document?.name!!, bytes))
                parcelFileDescriptor.close()
            }
        }
    }
}

@Composable
fun MainView(databases: List<Database>, openFile: () -> Unit) {
    var selectedDatabase by remember{mutableStateOf(null as Database?)}

    Column {
        HeaderView("Databases", Color.Cyan, openFile)
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
        PasswordOrMessageView(selectedDatabase)
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
fun PasswordOrMessageView(selectedDatabase: Database?) {
    if (selectedDatabase == null) {
        Spacer(modifier = Modifier.fillMaxHeight())
    } else {
        Spacer(modifier = Modifier.fillMaxHeight())
    }
}

@Preview(showBackground = true)
@Composable
fun MainViewPreview() {
    PmanTheme {
        MainView(listOf(
            Database("test", ByteArray(0)),
            Database("test2", ByteArray(0)
            ))) {}
    }
}