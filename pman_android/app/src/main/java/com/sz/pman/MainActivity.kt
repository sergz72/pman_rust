package com.sz.pman

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
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
import java.io.File
import android.Manifest
import android.app.AlertDialog
import android.content.Context
import android.os.ParcelFileDescriptor
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.Button
import androidx.core.content.ContextCompat
import java.io.FileDescriptor
import java.io.FileInputStream
import java.lang.Exception

const val PICK_FILE = 1

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        uniffi.pman_lib.libInit()

        setContent {
            PmanTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    Greeting("Android")
                }
            }
        }

        openFile()
    }

    private fun openFile() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/*"
        }

        startActivityForResult(intent, PICK_FILE)
    }

    //val contentResolver = applicationContext.contentResolver

    override fun onActivityResult(
        requestCode: Int, resultCode: Int, resultData: Intent?) {
        super.onActivityResult(requestCode, resultCode, resultData)
        if (requestCode == PICK_FILE
            && resultCode == Activity.RESULT_OK) {
            resultData?.data?.also { uri ->
                val dir = filesDir
                val parcelFileDescriptor: ParcelFileDescriptor? =
                    contentResolver.openFileDescriptor(uri, "r")
                val fileDescriptor: FileDescriptor = parcelFileDescriptor!!.fileDescriptor
                val stream = FileInputStream(fileDescriptor)
                val bytes = stream.readBytes()
                parcelFileDescriptor.close()
            }
        }
    }}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(
        text = "Hello $name!",
        modifier = modifier
    )
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    PmanTheme {
        Greeting("Android")
    }
}