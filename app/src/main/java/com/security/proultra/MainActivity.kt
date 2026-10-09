package com.security.proultra

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val inputField = findViewById<EditText>(R.id.inputDomain)
        val btnCheck = findViewById<Button>(R.id.btnLoopholeCheck)
        val resultView = findViewById<TextView>(R.id.txtResults)

        btnCheck.setOnClickListener {
            val targetUrl = inputField.text.toString().trim()
            if (targetUrl.isNotEmpty()) {
                resultView.text = "[*] Running SecurityProUltra Audit..."
                thread {
                    try {
                        val auditReport = checkSecurityLoopholes(targetUrl)
                        runOnUiThread {
                            resultView.text = auditReport
                        }
                    } catch (e: Exception) {
                        runOnUiThread {
                            resultView.text = "[X] Error during audit: ${e.localizedMessage}"
                        }
                    }
                }
            } else {
                resultView.text = "[!] Please enter a valid Domain or URL (e.g., example.com)"
            }
        }
    }

    private fun checkSecurityLoopholes(targetUrl: String): String {
        val report = StringBuilder()
        report.append("=== SecurityProUltra Audit Report ===\n\n")

        try {
            val formattedUrl = if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
                "https://$targetUrl"
            } else {
                targetUrl
            }

            val url = URL(formattedUrl)
            val connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 5000
            connection.connect()

            if (url.protocol.equals("http", ignoreCase = true)) {
                report.append("[!] HIGH RISK: Unencrypted HTTP protocol.\n")
            } else {
                report.append("[+] Secure Protocol: HTTPS active.\n")
            }

            if (connection.getHeaderField("Strict-Transport-Security") == null) {
                report.append("[-] Vulnerability: Missing HSTS header.\n")
            } else {
                report.append("[+] HSTS Header secured.\n")
            }

            if (connection.getHeaderField("Content-Security-Policy") == null) {
                report.append("[-] Vulnerability: Missing CSP header.\n")
            } else {
                report.append("[+] CSP Header secured.\n")
            }

            if (connection.getHeaderField("X-Frame-Options") == null) {
                report.append("[-] Vulnerability: Missing X-Frame-Options.\n")
            } else {
                report.append("[+] X-Frame-Options secured.\n")
            }

        } catch (e: Exception) {
            report.append("[X] Scan failed: ${e.message}\n")
        }

        return report.toString()
    }
}
