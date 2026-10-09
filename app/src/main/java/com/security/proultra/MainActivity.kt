package com.security.proultra

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.net.HttpURLConnection
import java.net.InetAddress
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
                resultView.text = "[*] Running Ultimate Security & Risk Audit...\nPlease wait..."
                
                thread {
                    val report = StringBuilder()
                    val cleanHost = rawInput.removePrefix("http://").removePrefix("https://").substringBefore("/")
                    
                    report.append("=== Target: $cleanHost ===\n\n")

                    var riskScore = 100 // Starting with full score, deducting for missing security headers

                    // 1. IP Address Lookup
                    try {
                        val address = InetAddress.getByName(cleanHost)
                        report.append("--- IP & Network Info ---\n")
                        report.append("IP Address: ${address.hostAddress}\n\n")
                    } catch (e: Exception) {
                        report.append("[!] IP Lookup Error: ${e.localizedMessage}\n\n")
                    }

                    // 2. HTTP Headers & Protocol Audit
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

                        report.append("--- Web Security Audit ---\n")
                        report.append("Protocol: ${url.protocol.uppercase()}\n")
                        if (url.protocol.equals("http", ignoreCase = true)) {
                            riskScore -= 30
                        }
                        
                        val hsts = connection.getHeaderField("Strict-Transport-Security")
                        report.append("HSTS Header: ${if (hsts != null) "Secure" else "Missing"}\n")
                        if (hsts == null) riskScore -= 20

                        val csp = connection.getHeaderField("Content-Security-Policy")
                        report.append("CSP Header: ${if (csp != null) "Secure" else "Missing"}\n")
                        if (csp == null) riskScore -= 20

                        // 3. SSL Certificate Details
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
                                riskScore -= 20
                            }
                        }
                    } catch (e: Exception) {
                        report.append("[X] Web Audit Error: ${e.localizedMessage}\n")
                        riskScore = 0
                    }

                    // 4. Port Scanner Audit
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

                    // Final Security Rating Summary
                    if (riskScore < 0) riskScore = 0
                    report.append("\n=============================\n")
                    report.append("Security Rating: $riskScore/100\n")
                    report.append(when {
                        riskScore >= 80 -> "Status: Highly Secure [OK]"
                        riskScore >= 50 -> "Status: Moderate Security [WARNING]"
                        else -> "Status: High Vulnerability [RISK]"
                    })
                    report.append("\n=============================\n")

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
