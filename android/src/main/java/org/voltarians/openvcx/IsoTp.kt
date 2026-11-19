// SPDX-License-Identifier: LGPL-3.0-only
package org.voltarians.openvcx

/** One physical ECU conversation; caller owns addressing and deadlines. */
class IsoTpReceiver(private val maximum: Int = 4095) {
    private var expected = 0
    private var sequence = 1
    private var data = java.io.ByteArrayOutputStream()
    sealed interface Result {
        data class Complete(val bytes: ByteArray): Result
        data class FlowControl(val bytes: ByteArray): Result
        data object Pending: Result
    }
    fun reset() { expected = 0; sequence = 1; data.reset() }
    fun accept(frame: ByteArray): Result {
        try {
            require(frame.size in 2..8)
            val pci = frame[0].toInt() and 255
            when (pci ushr 4) {
                0 -> {
                    require(expected == 0)
                    val size = pci and 15
                    require(size in 1..minOf(7,frame.size-1,maximum))
                    return Result.Complete(frame.copyOfRange(1,1+size))
                }
                1 -> {
                    require(expected == 0 && frame.size == 8)
                    expected = ((pci and 15) shl 8) or (frame[1].toInt() and 255)
                    require(expected in 8..minOf(4095,maximum))
                    data.write(frame,2,6)
                    return Result.FlowControl(byteArrayOf(0x30,0,0,0,0,0,0,0))
                }
                2 -> {
                    require(expected > 0 && (pci and 15) == sequence)
                    val count = minOf(expected-data.size(),frame.size-1)
                    require(count > 0 && (count == expected-data.size() || frame.size == 8))
                    data.write(frame,1,count)
                    sequence = (sequence+1) and 15
                    if (data.size() == expected) {
                        val result = data.toByteArray()
                        reset()
                        return Result.Complete(result)
                    }
                    return Result.Pending
                }
                else -> throw IllegalArgumentException("Unexpected ISO-TP frame")
            }
        } catch (e: IllegalArgumentException) { reset(); throw e }
    }
    companion object {
        fun singleFrame(payload: ByteArray): ByteArray {
            require(payload.size in 1..7)
            return ByteArray(8).also { it[0] = payload.size.toByte(); payload.copyInto(it,1) }
        }
    }
}
