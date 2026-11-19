// SPDX-License-Identifier: LGPL-3.0-only
package org.voltarians.openvcx

import android.os.SystemClock
import java.io.Closeable
import java.io.IOException
import java.nio.ByteBuffer

/** Exclusive owner of the USB link; no concurrent identity probe or reader. */
class VcxControlSession internal constructor(
    private val write: (ByteArray, Int) -> Unit,
    private val read: (Int) -> ByteArray,
    private val closeUsb: () -> Unit,
    private val clock: () -> Long,
) : Closeable {
    constructor(usb: VcxUsbTransport) : this(usb::write, usb::read, usb::close, SystemClock::elapsedRealtime)

    private val canFrames = ArrayDeque<VcxCanFrame>()
    private var authenticated = false
    private var channelOpen = false
    private val parser = VcxFrame.Parser()
    private var closed = false
    private var faulted = false
    private var identity: VcxIdentity? = null
    private var deviceInfo: ByteArray? = null

    @Synchronized fun identify(): VcxIdentity {
        check(!closed && !faulted)
        identity?.let { return it }
        val info = control(0x8c, 0, byteArrayOf(), 5000)
        if (!info.toString(Charsets.US_ASCII).contains("VCX-NANO"))
            throw IOException("Unqualified adapter identity")
        deviceInfo = info
        return VcxIdentity("VCX-NANO", info.size).also { identity = it }
    }

    /** Uses the installed PASSTHRU entitlement. A rejected session requires reopening USB. */
    @Synchronized fun establishPassThru() {
        check(!closed && !faulted)
        if (authenticated) return
        try {
            identify()
            VcxPassThruSession(
                transact = { opcode, data -> control(opcode, 0, data, 5000) },
                wallTimeMillis = System::currentTimeMillis,
                uptimeMillis = clock,
            ).establish(checkNotNull(deviceInfo))
            authenticated = true
        } catch (e: Exception) {
            faulted = true
            throw e
        }
    }

    @Synchronized internal fun connectCan(bitrate: Int) {
        require(bitrate == 250_000 || bitrate == 500_000)
        establishPassThru()
        if (channelOpen) disconnectCan()
        // Match the native driver's raw CAN setup on the primary diagnostic bus.
        channelOpen = true
        try {
            control(0x40, 0, byteArrayOf(0, 0, 0x81.toByte(), 1), 1000)
            control(0x45, 0, ByteBuffer.allocate(6).putShort(3).putInt(bitrate).array(), 1000)
            control(0x47, 0, byteArrayOf(1), 1000)
            control(0x42, 0, byteArrayOf(0), 1000)
            control(0x48, 0, byteArrayOf(1, 0, 1, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0), 1000)
        } catch (e: Exception) {
            runCatching { disconnectCan() }
            throw e
        }
    }

    @Synchronized internal fun disconnectCan() {
        if (!channelOpen) return
        try {
            control(0x43, 0, byteArrayOf(), 500, cleanup = true)
        } finally {
            try {
                control(0x41, 0, byteArrayOf(), 500, cleanup = true)
            } finally {
                channelOpen = false
                canFrames.clear()
            }
        }
    }

    @Synchronized internal fun voltage(): Double {
        val reply = control(0x86, 0, byteArrayOf(0x10), 1000)
        if (reply.size < 4) throw IOException("Invalid VCX voltage reply")
        return ByteBuffer.wrap(reply).int.toUInt().toDouble() / 1000
    }

    @Synchronized internal fun exchange(
        id: Int, payload: ByteArray, extended: Boolean, timeoutMs: Int,
    ): List<Pair<Int, ByteArray>> {
        check(channelOpen && !closed && !faulted)
        require(payload.size in 1..7 && timeoutMs > 0)
        val address = VcxObdAddress(id, extended)
        canFrames.clear()
        for (attempt in 1..4) {
            val pending = read(1)
            if (pending.isEmpty()) break
            parser.feed(pending)
        }
        sendCan(id, extended, IsoTpReceiver.singleFrame(payload))
        val deadline = clock() + timeoutMs
        val service = payload[0].toInt() and 255
        val receivers = mutableMapOf<Int, IsoTpReceiver>()
        val replies = mutableListOf<Pair<Int, ByteArray>>()
        while (clock() < deadline) {
            val frame = canFrames.removeFirstOrNull()
            if (frame == null) {
                readFrames(deadline)
                continue
            }
            val physicalId = address.flowControlId(frame) ?: continue
            // Only acknowledge a first frame from the service we requested.
            if (frame.data.size == 8 && frame.data[0].toInt() ushr 4 == 1 &&
                (frame.data[2].toInt() and 255) != service + 0x40
            ) continue
            val receiver = receivers.getOrPut(frame.id) { IsoTpReceiver() }
            val result = try {
                receiver.accept(frame.data)
            } catch (_: IllegalArgumentException) {
                continue
            }
            when (result) {
                is IsoTpReceiver.Result.FlowControl -> sendCan(physicalId, extended, result.bytes)
                is IsoTpReceiver.Result.Complete -> {
                    val response = result.bytes
                    val positive = response[0].toInt() and 255 == service + 0x40
                    val negative = response.size >= 3 && response[0] == 0x7f.toByte() && response[1] == payload[0]
                    if (!positive && !negative) continue
                    if (negative && response[2] == 0x78.toByte()) continue
                    if (!address.functional) return listOf(frame.id to response)
                    replies.add(frame.id to response)
                }
                IsoTpReceiver.Result.Pending -> Unit
            }
        }
        return replies
    }

    private fun sendCan(id: Int, extended: Boolean, data: ByteArray) {
        write(VcxFrame.encode(1, 0, 0, VcxCanFrame(id, extended, data).encode()), 1000)
    }

    private fun readFrames(deadline: Long): List<ByteArray> {
        val remaining = deadline - clock()
        if (remaining <= 0) return emptyList()
        return parser.feed(read(minOf(100, remaining).toInt())).also { frames ->
            if (channelOpen) {
                frames.mapNotNull(VcxCanFrame::decode).forEach { frame ->
                    if (canFrames.size >= 256) canFrames.removeFirst()
                    canFrames.addLast(frame)
                }
            }
        }
    }

    private fun control(
        opcode: Int, channel: Int, payload: ByteArray, timeoutMs: Int, cleanup: Boolean = false,
    ): ByteArray {
        check(!closed && (!faulted || cleanup))
        try {
            write(VcxFrame.encode(0, opcode, channel, payload), 1000)
            val deadline = clock() + timeoutMs
            while (clock() < deadline) {
                val frame = readFrames(deadline).firstOrNull {
                    it.size >= 5 && it[1].toInt() == 0 &&
                        (it[2].toInt() and 255) == opcode && (it[3].toInt() and 255) == channel
                } ?: continue
                val status = frame[4].toInt() and 255
                if (status != 0) throw IOException("VCX opcode 0x${opcode.toString(16)} rejected, status 0x${status.toString(16)}")
                return frame.copyOfRange(5, frame.size)
            }
            throw IOException("VCX opcode 0x${opcode.toString(16)} timed out")
        } catch (e: Exception) {
            faulted = true // Late replies must not be attributed to later requests.
            throw e
        }
    }

    @Synchronized override fun close() {
        if (closed) return
        try {
            disconnectCan()
        } finally {
            closed = true
            deviceInfo?.fill(0)
            deviceInfo = null
            closeUsb()
        }
    }
}
