// SPDX-License-Identifier: LGPL-3.0-only
package org.voltarians.openvcx

import java.nio.ByteBuffer

/** Raw CAN framing from OpenVCX's native driver. */
internal data class VcxCanFrame(val id: Int, val extended: Boolean, val data: ByteArray) {
    fun encode(): ByteArray = ByteBuffer.allocate(10 + data.size)
        .putInt(if (extended) EXTENDED else 0)
        .putShort((4 + data.size).toShort())
        .putInt(id)
        .put(data)
        .array()

    companion object {
        private const val EXTENDED = 0x100
        private const val NON_BUS_RX = 0x0b // TX indication, start of message, or TX done.

        fun decode(frame: ByteArray): VcxCanFrame? {
            if (frame.size !in 14..22 || frame[1].toInt() !in 0..1 ||
                frame[2].toInt() != 0 || frame[3].toInt() != 0
            ) return null
            val body = ByteBuffer.wrap(frame, 4, frame.size - 4)
            val flags = body.int
            val length = body.short.toInt()
            if (flags and NON_BUS_RX != 0 || length != body.remaining()) return null
            val id = body.int
            val extended = flags and EXTENDED != 0
            if (id !in 0..(if (extended) 0x1fffffff else 0x7ff)) return null
            return VcxCanFrame(id, extended, ByteArray(body.remaining()).also { body.get(it) })
        }
    }
}

internal class VcxObdAddress(private val requestId: Int, private val extended: Boolean) {
    val functional = requestId == if (extended) 0x18db33f1 else 0x7df

    init {
        require(functional || if (extended) requestId and 0x1fff00ff == 0x18da00f1
            else requestId in 0x7e0..0x7e7) { "Unsupported OBD ISO-TP request CAN ID" }
    }

    fun flowControlId(frame: VcxCanFrame): Int? {
        if (extended != frame.extended) return null
        if (!extended) {
            if (frame.id !in 0x7e8..0x7ef) return null
            val physicalId = frame.id - 8
            return physicalId.takeIf { functional || requestId == it }
        }
        if (frame.id and 0x1fffff00 != 0x18daf100) return null
        val physicalId = 0x18da00f1 or ((frame.id and 255) shl 8)
        return physicalId.takeIf { functional || requestId == it }
    }
}
