package dev.rubec.otoscope.vendor

import android.content.Context
import android.net.Network
import dev.rubec.otoscope.ble.CameraAdvert
import dev.rubec.otoscope.stream.CameraSession
import dev.rubec.otoscope.stream.xylla.XyllaSession

/**
 * Cameras advertising as `AIR-ES-XXXXXX`.
 *
 * Sold under the "Airlook" brand and paired with the "AIR-Look" companion
 * app. Technically the same hardware family as Xylla: identical BLE-advert
 * envelope (`0x66 0x99` magic + 6-byte BSSID), open AP, control channel on
 * UDP/50000 (battery cmd `0x1017`, board info `0x1060`), and the same
 * 24-byte-header MJPEG video channel on UDP/8032 with the `0x99 0x99`
 * start-preview command. We reuse [XyllaSession] unchanged.
 *
 * Registered before [XyllaVendor] so the SSID-name match wins on adverts
 * whose manufacturer data would otherwise be claimed by Xylla's magic check.
 */
object AirlookVendor : CameraVendor {
    override val displayName = "Airlook"
    override val discoveryMode = DiscoveryMode.BLE
    override val defaultCameraIp = "192.168.0.10"

    private const val NAME_PREFIX = "AIR-ES-"
    private val MAGIC = byteArrayOf(0x66, 0x99.toByte())

    override fun parseAdvert(
        bleAddress: String,
        deviceName: String?,
        scanRecord: ByteArray?,
        rssi: Int,
    ): CameraAdvert? {
        if (deviceName.isNullOrBlank()) return null
        if (!deviceName.startsWith(NAME_PREFIX, ignoreCase = true)) return null
        if (scanRecord == null) return null
        val payload = findManufacturerData(scanRecord, MAGIC) ?: return null
        if (payload.size < 6) return null
        val bssid = (0 until 6).joinToString(":") { "%02X".format(payload[it]) }
        return CameraAdvert(
            vendor = this,
            ssid = deviceName,
            bssid = bssid,
            wpa2Passphrase = null,
            bleAddress = bleAddress,
            rssi = rssi,
        )
    }

    override fun createSession(context: Context, network: Network?, cameraIp: String): CameraSession =
        XyllaSession(cameraIp = cameraIp, network = network)
}
