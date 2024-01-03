package com.sz.pman

import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.tooling.preview.Preview
import com.sz.pman.entities.DBEntity
import com.sz.pman.ui.theme.PmanTheme

@Composable
fun EntityView(entityToEdit: DBEntity) {

}

@Preview(showBackground = true)
@Composable
fun EntityViewPreview() {
    PmanTheme {
        EntityView(DBEntity(0U, null))
    }
}