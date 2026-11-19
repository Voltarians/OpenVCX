// SPDX-License-Identifier: LGPL-3.0-only
// Derived from OpenVCX vcx_transport.c, Erik Fuller and contributors.
package org.voltarians.openvcx

object VcxFrame {
    const val MAX_CONTENT = 4139
    fun encode(high: Int, opcode: Int, channel: Int, payload: ByteArray = byteArrayOf()): ByteArray {
        require(listOf(high, opcode, channel).all { it in 0..255 })
        require(payload.size <= MAX_CONTENT - 5)
        val content = byteArrayOf(0x80.toByte(), high.toByte(), opcode.toByte(), channel.toByte()) + payload
        val checksum = content.sumOf { it.toInt() and 255 }.toByte()
        val out = java.io.ByteArrayOutputStream()
        out.write(0xbb)
        for (b in content + checksum) {
            val v = b.toInt() and 255
            if (v == 0xbb || v == 0xee || v == 0xdd) {
                out.write(0xdd)
                out.write(v xor 255)
            } else out.write(v)
        }
        out.write(0xbb)
        return out.toByteArray()
    }

    class Parser {
        private val buffer = java.io.ByteArrayOutputStream()
        private var started = false
        private var escaped = false
        private var overflow = false
        var rejected = 0
            private set
        fun feed(bytes: ByteArray): List<ByteArray> {
            val frames = mutableListOf<ByteArray>()
            for (b in bytes) {
                var v = b.toInt() and 255
                if (v == 0xbb) {
                    val content = buffer.toByteArray()
                    if (overflow || escaped) rejected++
                    else if (content.isNotEmpty()) {
                        if (content.size >= 5 && (content[0].toInt() and 255) == 0x80 &&
                            (content.dropLast(1).sumOf { it.toInt() and 255 } and 255) ==
                            (content.last().toInt() and 255)) frames.add(content.copyOf(content.size - 1))
                        else rejected++
                    }
                    buffer.reset()
                    started = true
                    escaped = false
                    overflow = false
                    continue
                }
                if (!started || overflow) continue
                if (escaped) { v = v xor 255; escaped = false }
                else if (v == 0xdd) { escaped = true; continue }
                if (buffer.size() >= MAX_CONTENT) overflow = true else buffer.write(v)
            }
            return frames
        }
    }
}
