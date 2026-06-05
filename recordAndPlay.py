"""
Car Speed Rotator — Toggle-Based Telemetry Engine
Run as Administrator.

Controls:
- ARROWS: Normal Driving & Free Steering control during playback
- Press I: Toggle Recording ON/OFF (Beeps once)
- Press O: Toggle Playback ON/OFF (Beeps twice)
"""

import ctypes
import ctypes.wintypes
import math
import os
import struct
import sys
import time

# =============================================================================
# CONFIG (Pointer Chain & Offsets)
# =============================================================================
PROCESS_NAME = "forzahorizon6.exe"
Z_SPEED_CHAIN = ("forzahorizon6.exe", 0xA994A50, [0x10, 0x10, -0x548])

X_SPEED_OFFSET = -8
Z_SPEED_OFFSET = 0
STEER_OFFSET = 12

RECORD_FILE = "drift_run_recording.txt"
UPDATE_HZ = 30

TARGET_LEFT = -3.0
TARGET_RIGHT = 3.0
SNAP_SPEED = 0.04
GRIP_RATIO = -1.1
ACCEL_FACTOR = 1.0

# =============================================================================
# Windows API
# =============================================================================
k32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

PROCESS_ALL_ACCESS = 0x1F0FFF
TH32CS_SNAPPROCESS = 0x2
TH32CS_SNAPMODULE = 0x8
TH32CS_SNAPMODULE32 = 0x10

VK_LEFT = 0x25
VK_RIGHT = 0x27
VK_UP = 0x26
VK_DOWN = 0x28
VK_I = 0x49  # Toggle Record Key
VK_O = 0x4F  # Toggle Playback Key


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.wintypes.DWORD),
        ("cntUsage", ctypes.wintypes.DWORD),
        ("th32ProcessID", ctypes.wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", ctypes.wintypes.DWORD),
        ("cntThreads", ctypes.wintypes.DWORD),
        ("th32ParentProcessID", ctypes.wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("szExeFile", ctypes.c_char * 260),
    ]


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.wintypes.DWORD),
        ("th32ModuleID", ctypes.wintypes.DWORD),
        ("th32ProcessID", ctypes.wintypes.DWORD),
        ("GlblcntUsage", ctypes.wintypes.DWORD),
        ("ProccntUsage", ctypes.wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", ctypes.wintypes.DWORD),
        ("hModule", ctypes.wintypes.HMODULE),
        ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * 260),
    ]


def get_pid(name):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    k32.Process32First(snap, ctypes.byref(entry))
    while True:
        if entry.szExeFile.decode(errors="ignore").lower() == name.lower():
            k32.CloseHandle(snap)
            return entry.th32ProcessID
        if not k32.Process32Next(snap, ctypes.byref(entry)):
            break
    k32.CloseHandle(snap)
    return 0


def get_module_base(pid, name):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    entry = MODULEENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    k32.Module32First(snap, ctypes.byref(entry))
    while True:
        if entry.szModule.decode(errors="ignore").lower() == name.lower():
            base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value
            k32.CloseHandle(snap)
            return base
        if not k32.Module32Next(snap, ctypes.byref(entry)):
            break
    k32.CloseHandle(snap)
    return 0


def read_bytes(handle, addr, n):
    buf = ctypes.create_string_buffer(n)
    read = ctypes.c_size_t(0)
    k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, n, ctypes.byref(read))
    return buf.raw[: read.value]


def read_float(handle, addr):
    data = read_bytes(handle, addr, 4)
    return struct.unpack("<f", data)[0] if len(data) >= 4 else 0.0


def read_ptr(handle, addr):
    data = read_bytes(handle, addr, 8)
    return struct.unpack("<Q", data)[0] if len(data) >= 8 else 0


def write_float(handle, addr, value):
    buf = struct.pack("<f", float(value))
    written = ctypes.c_size_t(0)
    k32.WriteProcessMemory(
        handle, ctypes.c_void_p(addr), ctypes.c_char_p(buf), 4, ctypes.byref(written)
    )


def resolve_chain(handle, module_base, base_offset, offsets):
    addr = module_base + base_offset
    for off in offsets:
        ptr = read_ptr(handle, addr)
        if ptr == 0:
            return 0
        addr = ptr + off
    return addr


def key_pressed(vk, state_dict):
    """Detects a fresh single press down event instead of continuous state."""
    current_state = bool(user32.GetAsyncKeyState(vk) & 0x8000)
    was_down = state_dict.get(vk, False)
    state_dict[vk] = current_state
    return current_state and not was_down


# =============================================================================
# Core State Logic
# =============================================================================
is_recording = False
is_playing = False
recorded_frames = []
playback_index = 0
record_buffer = []
key_states = {}


def run_tick(handle, z_addr, current_steer):
    global \
        is_recording, \
        is_playing, \
        recorded_frames, \
        playback_index, \
        record_buffer, \
        key_states

    xs = read_float(handle, z_addr + X_SPEED_OFFSET)
    zs = read_float(handle, z_addr + Z_SPEED_OFFSET)

    up = key_down_raw = bool(user32.GetAsyncKeyState(VK_UP) & 0x8000)
    down = bool(user32.GetAsyncKeyState(VK_DOWN) & 0x8000)
    left = bool(user32.GetAsyncKeyState(VK_LEFT) & 0x8000)
    right = bool(user32.GetAsyncKeyState(VK_RIGHT) & 0x8000)

    # Track distinct key edge-triggers
    pressed_i = key_pressed(VK_I, key_states)
    pressed_o = key_pressed(VK_O, key_states)

    # 1. Handle Record Toggle
    if pressed_i:
        if not is_recording:
            # Turn ON Record
            is_playing = False  # Safety override
            is_recording = True
            record_buffer = []
            k32.Beep(300, 150)
            print(f"\n[*] Recording Started... Press 'I' again to save.")
        else:
            # Turn OFF Record & Flush
            is_recording = False
            k32.Beep(300, 300)
            try:
                with open(RECORD_FILE, "w") as f:
                    for mag, ang in record_buffer:
                        f.write(f"{mag},{ang}\n")
                print(
                    f"\n[+] Finished! Saved {len(record_buffer)} frames to '{RECORD_FILE}'!"
                )
                recorded_frames = list(record_buffer)
            except Exception as e:
                print(f"\n[!] Error saving layout profile: {e}")

    # 2. Handle Playback Toggle
    if pressed_o:
        if not is_playing:
            # Turn ON Playback
            is_recording = False  # Safety override
            playback_index = 0

            if not recorded_frames and os.path.exists(RECORD_FILE):
                try:
                    recorded_frames = []
                    with open(RECORD_FILE, "r") as f:
                        for line in f:
                            if line.strip():
                                parts = line.strip().split(",")
                                recorded_frames.append(
                                    (float(parts[0]), float(parts[1]))
                                )
                except Exception as e:
                    print(f"\n[!] Failed to reload file: {e}")

            if recorded_frames:
                is_playing = True
                k32.Beep(600, 100)
                k32.Beep(600, 100)
                print(f"\n[*] Playback Autopilot Engine Engaged.")
            else:
                print(f"\n[!] Empty Profile. Please record using 'I' first.")
        else:
            # Turn OFF Playback
            is_playing = False
            k32.Beep(400, 200)
            print(f"\n[*] Playback Cancelled.")

    # Process base manual steering
    if left and right:
        target_steer = 0.0
    elif left:
        target_steer = TARGET_LEFT
    elif right:
        target_steer = TARGET_RIGHT
    else:
        target_steer = 0.0

    current_steer += (target_steer - current_steer) * SNAP_SPEED
    if target_steer == 0.0 and abs(current_steer) < 0.005:
        current_steer = 0.0

    # Execute State 1: Active Live Recording
    if is_recording:
        magnitude = math.sqrt(xs * xs + zs * zs)
        angle = math.atan2(xs, zs)
        record_buffer.append((magnitude, angle))

        write_float(handle, z_addr + STEER_OFFSET, current_steer)

        theta = math.radians(GRIP_RATIO * current_steer)
        c = math.cos(theta)
        s = math.sin(theta)
        nx = xs * c - zs * s
        nz = xs * s + zs * c

        if up:
            nx *= ACCEL_FACTOR
        elif down:
            nx /= ACCEL_FACTOR * 1.02

        write_float(handle, z_addr + X_SPEED_OFFSET, nx)
        write_float(handle, z_addr + Z_SPEED_OFFSET, nz)

        return (
            f"[RECORDING] Live Frame Queue: {len(record_buffer)} | Grip Active",
            current_steer,
        )

    # Execute State 2: Automated Playback Execution
    elif is_playing:
        if playback_index < len(recorded_frames):
            p_mag, p_ang = recorded_frames[playback_index]

            nx = p_mag * math.sin(p_ang)
            nz = p_mag * math.cos(p_ang)
            write_float(handle, z_addr + X_SPEED_OFFSET, nx)
            write_float(handle, z_addr + Z_SPEED_OFFSET, nz)

            # Steering stays completely open for user manual adjustments
            write_float(handle, z_addr + STEER_OFFSET, current_steer)

            status_str = f"[PLAYBACK] Frame {playback_index}/{len(recorded_frames)} | Speed: {p_mag:.1f} | Steering Free"
            playback_index += 1
            return status_str, current_steer
        else:
            is_playing = False
            k32.Beep(400, 400)
            write_float(handle, z_addr + STEER_OFFSET, current_steer)
            return "[PLAYBACK COMPLETE] Reverted to standard drive", current_steer

    # Execute State 3: Default Driving
    else:
        write_float(handle, z_addr + STEER_OFFSET, current_steer)

        theta = math.radians(GRIP_RATIO * current_steer)
        c = math.cos(theta)
        s = math.sin(theta)
        nx = xs * c - zs * s
        nz = xs * s + zs * c

        if up:
            nx *= ACCEL_FACTOR
        elif down:
            nx /= ACCEL_FACTOR * 1.02

        write_float(handle, z_addr + X_SPEED_OFFSET, nx)
        write_float(handle, z_addr + Z_SPEED_OFFSET, nz)

        return (
            f"[DRIVE] Engine Ready. Profile Cache Size: {len(recorded_frames)}",
            current_steer,
        )


# =============================================================================
# Main Process Loop
# =============================================================================
def main():
    print(
        f"[*] Controls: ARROWS = Drive & Manual Angle | 'I' = Toggle Record | 'O' = Toggle Playback"
    )
    print(f"[*] Looking for {PROCESS_NAME}...")

    pid = get_pid(PROCESS_NAME)
    if not pid:
        print(f"[!] '{PROCESS_NAME}' not found. Is the game running?")
        sys.exit(1)

    print(f"[+] PID: {pid}")
    handle = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

    if not handle:
        print("[!] Failed to open process. Run as Administrator.")
        sys.exit(1)

    module_name, base_offset, chain_offsets = Z_SPEED_CHAIN
    module_base = get_module_base(pid, module_name)
    if not module_base:
        print(f"[!] Module '{module_name}' not found.")
        k32.CloseHandle(handle)
        sys.exit(1)

    print(f"[+] Module base: 0x{module_base:X}")
    print(f"[*] Running at {UPDATE_HZ}Hz. Ctrl+C to stop.\n")

    interval = 1.0 / UPDATE_HZ
    internal_steer = 0.0

    # Populating initial edge checks
    key_states[VK_I] = bool(user32.GetAsyncKeyState(VK_I) & 0x8000)
    key_states[VK_O] = bool(user32.GetAsyncKeyState(VK_O) & 0x8000)

    try:
        while True:
            t0 = time.perf_counter()
            z_addr = resolve_chain(handle, module_base, base_offset, chain_offsets)

            if z_addr == 0:
                print("[!] Pointer chain broken — waiting...", end="\r")
                time.sleep(1.0)
                continue

            status, internal_steer = run_tick(handle, z_addr, internal_steer)
            print(f"\r {status} \033[K", end="", flush=True)

            elapsed = time.perf_counter() - t0
            sleep_t = interval - elapsed
            if sleep_t > 0:
                time.sleep(sleep_t)

    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    finally:
        k32.CloseHandle(handle)


if __name__ == "__main__":
    main()
