package com.security.proultra

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
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
            val rawInput = inputField.text.toString().trim()
            if (rawInput.isNotEmpty()) {
                resultView.text = "[*] Running Deep Security Audit...\nPlease wait..."
                
                thread {
                    val report = StringBuilder()
                    val cleanHost = rawInput.removePrefix("http://").removePrefix("https://").substringBefore("/")
                    
                    report.append("=== Target: $cleanHost ===\n\n")

                    // 1. HTTP Headers & Protocol Audit
                    try {
                        val targetUrl = if (!rawInput.startsWith("http://") && !rawInput.startsWith("https://")) {
                            "https://$rawInput"
                        } else {
                            rawInput
                        }

                        val url = URL(targetUrl)
                        val connection = url.openConnection() as HttpURLConnection
                        connection.connectTimeout = 5000
                        connection.connect()

                        report.append("[+] Protocol: ${url.protocol.uppercase()}\n")
                        
                        val hsts = connection.getHeaderField("Strict-Transport-Security")
                        report.append("[-] HSTS Header: ${if (hsts != null) "Secure" else "Missing"}\n")

                        val csp = connection.getHeaderField("Content-Security-Policy")
                        report.append("[-] CSP Header: ${if (csp != null) "Secure" else "Missing"}\n")

                        // 2. SSL Certificate Details (If HTTPS)
                        if (connection is HttpsURLConnection) {
                            try {
                                val certs = connection.serverCertificates
                                if (certs.isNotEmpty()) {
                                    val cert = certs[0] as java.security.cert.X509Certificate
                                    report.append("\n--- SSL Certificate ---\n")
                                    report.append("Issuer: ${cert.issuerDN.name.substringAfter("CN=").substringBefore(",")}\n")
                                    report.append("Valid From: ${cert.notBefore}\n")
                                    report.append("Valid Until: ${cert.notAfter}\n")
                                }
                            } catch (e: Exception) {
                                report.append("\n[!] SSL Cert read error: ${e.message}\n")
                            }
                        }
                    } catch (e: Exception) {
                        report.append("[X] Web Audit Error: ${e.localizedMessage}\n")
                    }

                    // 3. Port Scanner Audit (Ports 80, 443, 8080)
                    report.append("\n--- Port Scan Results ---\n")
                    val portsToScan = intArrayOf(80, 443, 8080)
                    for (port in portsToScan) {
                        try {
                            val socket = Socket()
                            socket.connect(InetSocketAddress(cleanHost, port), 1500)
                            socket.close()
                            report.append("[OPEN] Port $port is active\n")
                        } catch (e: Exception) {
                            report.append("[CLOSED] Port $port\n")
                        }
                    }

                    runOnUiThread {
                        resultView.text = report.toString()
                    }
                }
            } else {
                resultView.text = "[!] Please enter a valid domain (e.g., google.com)"
            }
        }
    }
}
