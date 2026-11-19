// SPDX-License-Identifier: LGPL-3.0-only
package org.voltarians.openvcx

import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager

/** Backs ELM commands with the authenticated OpenVCX USB and CAN session. */
class VcxElmBackend internal constructor(private val session: VcxControlSession) : ElmBackend {
    companion object {
        /** Call on a worker thread after obtaining Android USB permission. */
        fun open(manager: UsbManager, device: UsbDevice): VcxElmBackend =
            VcxElmBackend(VcxControlSession(VcxUsbTransport.open(manager, device)))
    }

    override fun connect(bitrate: Int, extended: Boolean) = session.connectCan(bitrate)

    override fun exchange(
        id: Int, payload: ByteArray, extended: Boolean, timeoutMs: Int,
    ): List<Pair<Int, ByteArray>> = session.exchange(id, payload, extended, timeoutMs)

    override fun voltage(): Double = session.voltage()
    override fun disconnect() = session.disconnectCan()
    override fun close() = session.close()
}
