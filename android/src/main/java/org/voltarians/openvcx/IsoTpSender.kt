// SPDX-License-Identifier: LGPL-3.0-only
package org.voltarians.openvcx

/** Physical-address ISO-TP sender. Caller transmits frames and enforces deadlines. */
class IsoTpSender(payload: ByteArray) {
    private val bytes = payload.copyOf()
    private var offset = 0
    private var sequence = 1
    private var credit = 0
    private var unlimited = false
    private var waits = 0
    private var started = false
    var separationMicros = 0
        private set
    val complete get() = started && offset == bytes.size
    val awaitingFlowControl get() = started && !complete && credit == 0 && !unlimited
    init { require(bytes.size in 1..4095) }
    fun start(): ByteArray {
        check(!started)
        started = true
        if (bytes.size <= 7) {
            offset = bytes.size
            return IsoTpReceiver.singleFrame(bytes)
        }
        return ByteArray(8).also {
            it[0] = (0x10 or (bytes.size shr 8)).toByte()
            it[1] = bytes.size.toByte()
            bytes.copyInto(it,2,0,6)
            offset = 6
        }
    }
    fun flowControl(frame: ByteArray) {
        check(awaitingFlowControl)
        require(frame.size in 3..8 && (frame[0].toInt() and 0xf0) == 0x30)
        when (frame[0].toInt() and 15) {
            0 -> {
                val st = frame[2].toInt() and 255
                separationMicros = when(st) {
                    in 0..127 -> st*1000
                    in 0xf1..0xf9 -> (st-0xf0)*100
                    else -> throw IllegalArgumentException("Reserved STmin")
                }
                credit = frame[1].toInt() and 255
                unlimited = credit == 0
                waits = 0
            }
            1 -> { check(++waits <= 3) { "Flow-control wait limit" } }
            2 -> throw IllegalStateException("Receiver overflow")
            else -> throw IllegalArgumentException("Invalid flow status")
        }
    }
    /** Caller must wait at least separationMicros between consecutive frames. */
    fun nextFrame(): ByteArray {
        check(started && !complete && (unlimited || credit > 0))
        val end = minOf(offset+7,bytes.size)
        val frame = ByteArray(8)
        frame[0] = (0x20 or sequence).toByte()
        bytes.copyInto(frame,1,offset,end)
        offset = end
        sequence = (sequence+1) and 15
        if (!unlimited) credit--
        return frame
    }
}
