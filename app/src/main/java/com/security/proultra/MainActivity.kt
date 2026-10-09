package com.security.proultra

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.net.InetAddress
import java.net.URL
import javax.net.ssl.HttpsURLConnection
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
                resultView.text = "[*] Initializing SecurityProUltra Deep Diagnostic...\n[*] Analyzing headers & SSL certificate..."
                thread {
                    val auditReport = performProUltraAudit(targetUrl)
                    runOnUiThread {
                        resultView.text = auditReport
                    }
                }
            } else {
                resultView.text = "[!] Error: Please enter a valid URL or Domain (e.g., example.com)"
            }
        }
    }

    private fun performProUltraAudit(targetUrl: String): String {
        val report = StringBuilder()
        report.append("====================================\n")
        report.append("   SECURITYPRO-ULTRA AUDIT v3.0     \n")
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
                report.append("[-] DNS Warning: IP resolution failed.\n\n")
            }

            val url = URL(formattedUrl)

            // 2. HTTPS & SSL Certificate Inspection
            if (url.protocol.equals("https", ignoreCase = true)) {
                try {
                    val connection = url.openConnection() as HttpsURLConnection
                    connection.requestMethod = "GET"
                    connection.connectTimeout = 6000
                    connection.connect()

                    report.append("--- SSL / TLS Certificate Info ---\n")
                    val certs = connection.serverCertificates
                    if (certs.isNotEmpty()) {
                        val cert = certs[0] as java.security.cert.X509Certificate
                        report.append("[+] Issuer: ${cert.issuerDN.name.take(40)}...\n")
                        report.append("[+] Valid From: ${cert.notBefore}\n")
                        report.append("[+] Valid Until: ${cert.notAfter}\n")
                        report.append("[+] Secure TLS Connection: Active\n\n")
                    }
                } catch (e: Exception) {
                    report.append("[-] SSL Warning: Could not fetch certificate details (${e.message})\n\n")
                }
            } else {
                report.append("[!] CRITICAL: Unencrypted HTTP protocol in use!\n\n")
            }

            // 3. Security Headers Inspection
            val connection = url.openConnection() as java.net.HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 6000
            connection.connect()

            report.append("--- Security Headers Analysis ---\n")

            val hsts = connection.getHeaderField("Strict-Transport-Security")
            if (hsts == null) report.append("[-] VULNERABILITY: Missing HSTS Header\n")
            else report.append("[+] PASSED: HSTS Active\n")

            val csp = connection.getHeaderField("Content-Security-Policy")
            if (csp == null) report.append("[-] VULNERABILITY: Missing CSP Header\n")
            else report.append("[+] PASSED: CSP Configured\n")

            val xFrame = connection.getHeaderField("X-Frame-Options")
            if (xFrame == null) report.append("[-] VULNERABILITY: Missing X-Frame-Options (Clickjacking Risk)\n")
            else report.append("[+] PASSED: X-Frame-Options Secure\n")

            val xContentType = connection.getHeaderField("X-Content-Type-Options")
            if (xContentType == null) report.append("[-] WARNING: Missing X-Content-Type-Options\n")
            else report.append("[+] PASSED: X-Content-Type-Options present\n")

            report.append("\n====================================\n")
            report.append("[*] Audit Completed Successfully.")

        } catch (e: Exception) {
            report.append("[X] Scan Execution Failed: ${e.localizedMessage}\n")
        }

        return report.toString()
    }
}
