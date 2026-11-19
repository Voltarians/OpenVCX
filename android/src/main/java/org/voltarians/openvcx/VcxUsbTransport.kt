// SPDX-License-Identifier: LGPL-3.0-only
package org.voltarians.openvcx

import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import com.hoho.android.usbserial.driver.UsbSerialProber
import com.hoho.android.usbserial.driver.UsbSerialPort
import java.io.Closeable
import java.io.IOException

/** Call on a worker thread after Android USB permission is granted. */
class VcxUsbTransport private constructor(private val port: UsbSerialPort) : Closeable {
    companion object {
        fun candidates(manager: UsbManager): List<UsbDevice> =
            UsbSerialProber.getDefaultProber().findAllDrivers(manager)
                .map { it.device }.filter { it.vendorId == 0x1a86 }

        fun open(manager: UsbManager, device: UsbDevice): VcxUsbTransport {
            require(device.vendorId == 0x1a86) { "Expected WCH USB serial candidate" }
            require(manager.hasPermission(device)) { "USB permission required" }
            val driver = UsbSerialProber.getDefaultProber().probeDevice(device)
                ?: throw IOException("Unsupported USB serial bridge")
            val connection = manager.openDevice(device) ?: throw IOException("USB open failed")
            val port = driver.ports.first()
            try {
                port.open(connection)
                port.setParameters(921600, 8, UsbSerialPort.STOPBITS_1, UsbSerialPort.PARITY_NONE)
                port.dtr = true
                port.rts = true
                return VcxUsbTransport(port)
            } catch (e: Exception) {
                runCatching { port.close() }
                connection.close()
                throw e
            }
        }
    }

    @Synchronized fun write(frame: ByteArray, timeoutMs: Int = 1000) {
        require(timeoutMs > 0)
        port.write(frame, timeoutMs)
    }

    @Synchronized fun read(timeoutMs: Int = 100): ByteArray {
        require(timeoutMs > 0)
        val buffer = ByteArray(4096)
        val count = port.read(buffer, timeoutMs)
        return buffer.copyOf(count)
    }

    @Synchronized override fun close() { port.close() }
}
