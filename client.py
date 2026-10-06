#!/usr/bin/env python3
"""AIR-Look WiFi Ear Camera Client"""

import socket
import struct
import json
import time
import threading
import queue
import cv2
import numpy as np
from typing import Optional

DISCOVERY_PORT = 50000
VIDEO_PORT = 8032
CONTROL_PORT = 7060

DISCOVERY_MAGIC = b"\x99\x99"
STATUS_REQUEST = DISCOVERY_MAGIC + b"\x17\x10" + b"\x00" * 20
START_CMD = b"\x99\x99\x01\x00" + b"\x00" * 20

PKT_SOI = 0x01
PKT_CONT = 0x03
PKT_EOI = 0x02

# Status packet offsets (from pcap analysis)
# type=1710 response payload:
#   bytes 2-3 (LE u16): battery millivolts (e.g. 4013 mV)
#   byte 10:            battery percentage (e.g. 94%)


class AirLookClient:
    def __init__(self, device_ip: str = "192.168.0.10"):
        self.device_ip = device_ip
        self.running = False
        self.frame_queue = queue.Queue(maxsize=30)
        self.frame_count = 0
        self.pkt_count = 0
        self.sock = None
        self.tcp_sock = None
        self.battery_pct: Optional[int] = None
        self.battery_mv: Optional[int] = None

    def discover(self, timeout: float = 2.0) -> Optional[dict]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(
            DISCOVERY_MAGIC + b"\x60\x10\xe2\x04" + b"\x00" * 18,
            (self.device_ip, DISCOVERY_PORT),
        )
        try:
            resp, _ = sock.recvfrom(4096)
            if resp[:2] == DISCOVERY_MAGIC:
                s, e = resp.find(b"{"), resp.rfind(b"}") + 1
                if s >= 0:
                    return json.loads(resp[s:e].decode())
        except socket.timeout:
            pass
        finally:
            sock.close()
        return None

    def keepalive_loop(self):
        """Send video heartbeat every 600ms + poll battery status on same cadence.

        Battery poll: send 9999 1710 <cmd_id LE> + 18 zeros from a fresh ephemeral
        socket each time (matches app behaviour in pcap - each request uses a new
        source port). Device echoes the same 9999 1710 header with status payload.
        """
        cmd_id = 0x04E2
        tick = 0

        while self.running:
            try:
                # Video heartbeat
                self.sock.sendto(START_CMD, (self.device_ip, VIDEO_PORT))

                # Battery poll every 3 ticks (~1.8s)
                if tick % 3 == 0:
                    req = (
                        DISCOVERY_MAGIC
                        + b"\x17\x10"
                        + struct.pack("<H", cmd_id)
                        + b"\x00" * 18
                    )
                    # Fresh socket per request - device replies to source port
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(0.5)
                    try:
                        s.sendto(req, (self.device_ip, DISCOVERY_PORT))
                        resp, _ = s.recvfrom(256)
                        # Response: 9999 1710 <cmd_id> <payload>
                        if (
                            resp[:4] == DISCOVERY_MAGIC + b"\x17\x10"
                            and len(resp) >= 18
                        ):
                            payload = resp[6:]
                            mv = struct.unpack("<H", payload[2:4])[0]
                            pct = payload[10]
                            if 3000 < mv < 5000 and 0 <= pct <= 100:
                                self.battery_mv = mv
                                self.battery_pct = pct
                    except socket.timeout:
                        pass
                    finally:
                        s.close()
                    cmd_id += 1

            except Exception:
                pass

            tick += 1
            time.sleep(0.6)

    def connect_tcp(self):
        """Try TCP connection in background, silently skip if refused"""

        def _try():
            for attempt in range(5):
                if not self.running:
                    return
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
                    sock.connect((self.device_ip, CONTROL_PORT))
                    self.tcp_sock = sock
                    print(f"TCP connected to port {CONTROL_PORT}")
                    return
                except ConnectionRefusedError:
                    time.sleep(1.0)
                except Exception:
                    return

        threading.Thread(target=_try, daemon=True).start()

    def receive_loop(self):
        frame_data = b""
        frame_id = -1

        while self.running:
            try:
                data, _ = self.sock.recvfrom(2048)
                self.pkt_count += 1

                if len(data) < 24 or data[0] != 0x66:
                    continue

                pkt_type = data[1]
                pkt_fid = struct.unpack(">H", data[4:6])[0]
                payload = data[24:]

                if pkt_type == PKT_SOI:
                    frame_data = payload
                    frame_id = pkt_fid
                elif pkt_type == PKT_CONT and pkt_fid == frame_id:
                    frame_data += payload
                elif pkt_type == PKT_EOI:
                    frame_data += payload
                    s, e = frame_data.find(b"\xff\xd8"), frame_data.rfind(b"\xff\xd9")
                    if s >= 0 and e > s:
                        self.frame_count += 1
                        jpeg = frame_data[s : e + 2]
                        if self.frame_queue.full():
                            try:
                                self.frame_queue.get_nowait()
                            except queue.Empty:
                                pass
                        try:
                            self.frame_queue.put_nowait(jpeg)
                        except queue.Full:
                            pass
                    frame_data = b""
                else:
                    if pkt_fid != frame_id:
                        frame_data = b""
                        frame_id = -1

            except socket.timeout:
                pass
            except Exception as e:
                if self.running:
                    print(f"  Error: {e}")

    def _draw_battery(self, frame: np.ndarray) -> np.ndarray:
        """Draw battery indicator in top-left corner"""
        pct = self.battery_pct
        mv = self.battery_mv

        # Show placeholder if not yet received
        display_pct = pct if pct is not None else 0
        display_mv = mv if mv is not None else 0

        if pct is None:
            colour = (120, 120, 120)
        elif pct > 50:
            colour = (0, 200, 0)
        elif pct > 20:
            colour = (0, 165, 255)
        else:
            colour = (0, 0, 220)

        font = cv2.FONT_HERSHEY_SIMPLEX
        bx, by = 10, 10
        bw, bh = 54, 24

        # Dark background for contrast
        cv2.rectangle(
            frame, (bx - 4, by - 4), (bx + bw + 14, by + bh + 18), (0, 0, 0), -1
        )

        # Battery body
        cv2.rectangle(frame, (bx, by), (bx + bw, by + bh), (200, 200, 200), 2)
        # Terminal nub
        cv2.rectangle(
            frame, (bx + bw, by + 7), (bx + bw + 5, by + bh - 7), (200, 200, 200), -1
        )
        # Fill bar
        fill_w = int((bw - 4) * display_pct / 100)
        if fill_w > 0:
            cv2.rectangle(
                frame, (bx + 2, by + 2), (bx + 2 + fill_w, by + bh - 2), colour, -1
            )

        # Percentage text inside battery
        text = f"{display_pct}%" if pct is not None else "?%"
        ts = cv2.getTextSize(text, font, 0.45, 1)[0]
        cv2.putText(
            frame,
            text,
            (bx + (bw - ts[0]) // 2, by + bh - 5),
            font,
            0.45,
            (255, 255, 255),
            1,
            cv2.LINE_AA,
        )

        # mV below battery
        mv_text = f"{display_mv}mV" if mv is not None else "---mV"
        cv2.putText(
            frame,
            mv_text,
            (bx, by + bh + 14),
            font,
            0.38,
            (180, 180, 180),
            1,
            cv2.LINE_AA,
        )

        return frame

    def run(self, display: bool = True):
        print(f"Discovering {self.device_ip}...")
        info = self.discover()
        print(f"Found: {info.get('model', 'Unknown')}" if info else "No response")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
        self.sock.bind(("0.0.0.0", 0))
        self.sock.settimeout(5.0)
        print(f"Bound to port {self.sock.getsockname()[1]}")

        self.connect_tcp()
        self.running = True

        ka = threading.Thread(target=self.keepalive_loop, daemon=True)
        ka.start()
        rx = threading.Thread(target=self.receive_loop, daemon=True)
        rx.start()

        time.sleep(0.1)
        print("Sending start command...")
        self.sock.sendto(START_CMD, (self.device_ip, VIDEO_PORT))

        print("\nPress 'q' or close the window to quit\n")

        if display:
            cv2.namedWindow("AIR-Look", cv2.WINDOW_AUTOSIZE)

        try:
            while self.running:
                try:
                    jpeg = self.frame_queue.get(timeout=0.05)
                    if display:
                        frame = cv2.imdecode(
                            np.frombuffer(jpeg, np.uint8), cv2.IMREAD_COLOR
                        )
                        if frame is not None:
                            frame = cv2.rotate(frame, cv2.ROTATE_90_CLOCKWISE)
                            frame = self._draw_battery(frame)
                            cv2.imshow("AIR-Look", frame)
                except queue.Empty:
                    pass

                if display:
                    if (
                        cv2.waitKey(1) & 0xFF == ord("q")
                        or cv2.getWindowProperty("AIR-Look", cv2.WND_PROP_VISIBLE) < 1
                    ):
                        break
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            rx.join(timeout=1)
            if self.tcp_sock:
                self.tcp_sock.close()
            if self.sock:
                self.sock.close()
            cv2.destroyAllWindows()
            print(f"\nTotal: {self.frame_count} frames")


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--ip", default="192.168.0.10")
    p.add_argument("--no-display", action="store_true")
    args = p.parse_args()
    AirLookClient(args.ip).run(display=not args.no_display)
