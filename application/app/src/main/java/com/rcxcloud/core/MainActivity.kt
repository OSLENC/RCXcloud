package com.rcxcloud.core

import android.app.Activity
import android.os.Bundle
import android.widget.TextView
import android.widget.LinearLayout
import android.widget.Button
import android.graphics.Color

class MainActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Simple programmatic UI (No XML needed for test)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.BLACK)
            setPadding(50, 50, 50, 50)
        }

        val statusText = TextView(this).apply {
            text = "RCX Secure Core: Loading..."
            textSize = 18f
            setTextColor(Color.WHITE)
        }
        layout.addView(statusText)

        val testBtn = Button(this).apply {
            text = "Run Diagnostics"
            setOnClickListener {
                runTests(statusText)
            }
        }
        layout.addView(testBtn)

        setContentView(layout)
    }

    private fun runTests(log: TextView) {
        val sb = StringBuilder()
        
        // 1. Check Kill State
        val killed = SecureCore.isKilled()
        sb.append("Kill Switch: ${if (killed == 1) "ACTIVATED" else "SAFE"}\n")

        // 2. Encrypt Test
        val raw = "Hello Termux!".toByteArray()
        val enc = SecureCore.encryptChunk(1001L, 1, 0, raw)
        
        if (enc != null) {
            sb.append("Encryption: SUCCESS (${enc.size} bytes)\n")
            
            // 3. Decrypt Test
            val dec = SecureCore.decryptChunk(1001L, 1, 0, enc)
            if (dec != null && dec.contentEquals(raw)) {
                sb.append("Decryption: VERIFIED ✅\n")
            } else {
                sb.append("Decryption: FAILED ❌\n")
            }
        } else {
            sb.append("Encryption: FAILED ❌\n")
        }

        log.text = sb.toString()
    }
}
