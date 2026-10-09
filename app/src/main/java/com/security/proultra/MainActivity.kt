package com.security.proultra

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.net.HttpURLConnection
import java.net.InetAddress
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
                resultView.text = "[*] Initializing SecurityProUltra Advanced Scanner...\n[*] Resolving target & fetching headers..."
                thread {
                    val auditReport = performAdvancedAudit(targetUrl)
                    runOnUiThread {
                        resultView.text = auditReport
                    }
                }
            } else {
                resultView.text = "[!] Error: Please enter a valid URL or Domain (e.g., example.com)"
            }
        }
    }

    private fun performAdvancedAudit(targetUrl: String): String {
        val report = StringBuilder()
        report.append("====================================\n")
        report.append("    SECURITYPRO-ULTRA AUDIT v2.0    \n")
        report.append("====================================\n\n")

        try {
            val cleanHost = targetUrl.replace("http://", "").replace("https://", "").trim().split("/")[0]
            val formattedUrl = if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
                "https://$targetUrl"
            } else {
                targetUrl
            }

            // 1. DNS / IP Resolution
            try {
                val address = InetAddress.getByName(cleanHost)
                report.append("[+] Target Host: $cleanHost\n")
                report.append("[+] Resolved IP: ${address.hostAddress}\n\n")
            } catch (e: Exception) {
                report.append("[-] DNS Resolution Warning: Could not resolve IP.\n\n")
            }

            // 2. Connection & Headers Analysis
            val url = URL(formattedUrl)
            val connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 6000
            connection.readTimeout = 6000
            connection.connect()

            val responseCode = connection.responseCode
            report.append("[*] HTTP Response Code: $responseCode\n")

            if (url.protocol.equals("http", ignoreCase = true)) {
                report.append("[!] CRITICAL: Unencrypted HTTP protocol! Data in transit can be intercepted.\n\n")
            } else {
                report.append("[+] SECURE: HTTPS protocol enforced.\n\n")
            }

            report.append("--- Header Security Analysis ---\n")

            // HSTS Check
            val hsts = connection.getHeaderField("Strict-Transport-Security")
            if (hsts == null) {
                report.append("[-] VULNERABILITY: Missing HSTS Header\n")
            } else {
                report.append("[+] PASSED: HSTS Active ($hsts)\n")
            }

            // CSP Check
            val csp = connection.getHeaderField("Content-Security-Policy")
            if (csp == null) {
                report.append("[-] VULNERABILITY: Missing Content-Security-Policy (CSP)\n")
            } else {
                report.append("[+] PASSED: CSP Configured\n")
            }

            // X-Frame-Options Check
            val xFrame = connection.getHeaderField("X-Frame-Options")
            if (xFrame == null) {
                report.append("[-] VULNERABILITY: Missing X-Frame-Options (Clickjacking Risk)\n")
            } else {
                report.append("[+] PASSED: X-Frame-Options ($xFrame)\n")
            }

            // X-Content-Type-Options Check
            val xContentType = connection.getHeaderField("X-Content-Type-Options")
            if (xContentType == null) {
                report.append("[-] WARNING: Missing X-Content-Type-Options (MIME-sniffing risk)\n")
            } else {
                report.append("[+] PASSED: X-Content-Type-Options present\n")
            }

            // Server Disclosure
            val server = connection.getHeaderField("Server")
            if (server != null) {
                report.append("[!] INFO: Server software disclosed -> $server\n")
            } else {
                report.append("[+] SECURE: Server banner hidden.\n")
            }

            report.append("\n====================================\n")
            report.append("[*] Advanced Audit Completed Successfully.")

        } catch (e: Exception) {
            report.append("[X] Scan Execution Failed: ${e.localizedMessage}\n")
            report.append("[*] Tip: Verify if the domain is live and reachable.")
        }

        return report.toString()
    }
}
