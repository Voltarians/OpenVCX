// SPDX-License-Identifier: LGPL-3.0-only
package org.voltarians.openvcx

interface ElmBackend {
    fun connect(bitrate: Int, extended: Boolean)
    fun exchange(id: Int, payload: ByteArray, extended: Boolean, timeoutMs: Int): List<Pair<Int, ByteArray>>
    fun voltage(): Double
    fun close()
}

class Elm327(private val backend: ElmBackend) {
    private var echo = true
    private var spaces = true
    private var lines = true
    private var headers = false
    private var protocol = 0
    private var connected = false
    private var header: Int? = null
    private var filter: Int? = null
    private var timeout = 200
    private var previous = ""
    private fun reset() {
        backend.close()
        connected = false
        echo = true; spaces = true; lines = true; headers = false
        protocol = 0; header = null; filter = null; timeout = 200; previous = ""
    }
    @Synchronized fun command(raw: String): String {
        val cmd = raw.filterNot { it.isWhitespace() }.uppercase().ifEmpty { previous }
        previous = cmd
        val prefix = if (echo && raw.isNotBlank()) raw.trim()+"\r" else ""
        val result = try { execute(cmd) } catch (e: Exception) { connected = false; runCatching { backend.close() }; "CAN ERROR" }
        val sep = if (lines) "\r\n" else "\r"
        return prefix + result.replace("\n",sep) + sep + ">"
    }
    private fun execute(cmd: String): String {
        when(cmd) {
            "ATZ","ATWS" -> { reset(); return "OpenVCX ELM327" }
            "ATD" -> { reset(); return "OK" }
            "ATI","AT@1" -> return "OpenVCX ELM327"
            "ATRV" -> return java.lang.String.format(java.util.Locale.US,"%.1fV",backend.voltage())
            "ATDPN" -> return if(protocol == 0) { if(connected) "A6" else "0" } else protocol.toString()
            "ATDP" -> return if(protocol == 0 && !connected) "AUTO" else "ISO 15765-4 (CAN)"
            "ATCRA" -> { filter = null; return "OK" }
        }
        if (cmd.matches(Regex("AT[ESLH][01]"))) {
            val enabled = cmd.last() == '1'
            when(cmd[2]) { 'E' -> echo=enabled; 'S' -> spaces=enabled; 'L' -> lines=enabled; 'H' -> headers=enabled }
            return "OK"
        }
        if (cmd.matches(Regex("ATSP[06789]"))) {
            backend.close(); connected=false; protocol=cmd.last().digitToInt(); header=null; filter=null
            return "OK"
        }
        if (cmd.matches(Regex("ATST[0-9A-F]{2}"))) {
            timeout = (cmd.takeLast(2).toInt(16)*4).coerceAtLeast(4); return "OK"
        }
        if (cmd.matches(Regex("AT(SH|CRA)([0-9A-F]{3}|[0-9A-F]{8})"))) {
            val isHeader = cmd.startsWith("ATSH")
            val digits = cmd.substring(if(isHeader) 4 else 5)
            val id = digits.toLong(16)
            val extended = protocol == 7 || protocol == 9
            if (digits.length != (if(extended) 8 else 3) || id > (if(extended) 0x1fffffffL else 0x7ffL)) return "?"
            if(isHeader) header=id.toInt() else filter=id.toInt()
            return "OK"
        }
        if (!cmd.matches(Regex("([0-9A-F]{2}){1,7}"))) return "?"
        val bytes = cmd.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        if ((bytes[0].toInt() and 255) !in setOf(1,3,7,9,10,34)) return "?"
        val extended = protocol == 7 || protocol == 9
        if(!connected) {
            backend.connect(if(protocol == 8 || protocol == 9) 250000 else 500000,extended)
            connected=true
        }
        val rows = backend.exchange(header ?: if(extended) 0x18db33f1 else 0x7df,bytes,extended,timeout)
        val join = if(spaces) " " else ""
        return rows.filter { filter == null || it.first == filter }.joinToString("\n") { (id,data) ->
            val parts = data.map { "%02X".format(it.toInt() and 255) }
            (if(headers) listOf(if(extended) "%08X".format(id) else "%03X".format(id))+parts else parts).joinToString(join)
        }.ifEmpty { "NO DATA" }
    }
}
