"""
Car Speed Rotator — Grip Default Engine (LCTRL to Drift)
Run as Administrator.
"""

import ctypes
import ctypes.wintypes
import math
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

# =============================================================================
# DYNAMIC PHYSICS CONFIG
# =============================================================================
TARGET_LEFT = -3.0
TARGET_RIGHT = 3.0
SNAP_SPEED = 0.04

GRIP_RATIO = -1.1  # Normal driving = GRIP (Car stays on rails)
DRIFT_RATIO = 0.2  # Holding Left Control = DRIFT (Initiates slide)

ACCEL_FACTOR = 1.0  # + 64e-4  # + 1e-5
UPDATE_HZ = 30

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
VK_LCTRL = 0xA2  # Left Control Key


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


def key_down(vk):
    return bool(user32.GetAsyncKeyState(vk) & 0x8000)


# =============================================================================
# Core Logic
# =============================================================================
def run_tick(handle, z_addr, current_steer):
    xs = read_float(handle, z_addr + X_SPEED_OFFSET)
    zs = read_float(handle, z_addr + Z_SPEED_OFFSET)

    up = key_down(VK_UP)
    down = key_down(VK_DOWN)
    left = key_down(VK_LEFT)
    right = key_down(VK_RIGHT)
    lctrl = key_down(VK_LCTRL)

    if left and right:
        target_steer = 0.0
    elif left:
        target_steer = TARGET_LEFT
    elif right:
        target_steer = TARGET_RIGHT
    else:
        target_steer = 0.0

    # Key Modifier Logic using clean variable names
    if lctrl:
        active_ratio = DRIFT_RATIO  # 2.0 (Drift)
        mode_label = "DRIFT"
    else:
        active_ratio = GRIP_RATIO  # -2.0 (Grip)
        mode_label = "GRIP "

    # Interpolate steering input
    current_steer += (target_steer - current_steer) * SNAP_SPEED

    if target_steer == 0.0 and abs(current_steer) < 0.005:
        current_steer = 0.0

    write_float(handle, z_addr + STEER_OFFSET, current_steer)

    # Process physics rotation vector
    theta = math.radians(active_ratio * current_steer)
    c = math.cos(theta)
    s = math.sin(theta)

    nx = xs * c - zs * s
    nz = xs * s + zs * c

    if up:
        nx = nx * ACCEL_FACTOR
        nz = nz * ACCEL_FACTOR
    elif down:
        denom = ACCEL_FACTOR * 1.02
        nx = nx / denom
        nz = nz / denom

    write_float(handle, z_addr + X_SPEED_OFFSET, nx)
    write_float(handle, z_addr + Z_SPEED_OFFSET, nz)

    direction = (
        "LEFT " if current_steer > 0.05 else "RIGHT" if current_steer < -0.05 else "--"
    )
    status_str = f"[{mode_label}] ratio={active_ratio:+.1f} steer={current_steer:+.2f} [{direction}]"

    return status_str, current_steer


# =============================================================================
# Main Process Loop
# =============================================================================
def main():
    print(
        f"[*] Controls: ARROWS = Grip Driving ({GRIP_RATIO}) | Hold LCTRL = Drift Mode ({DRIFT_RATIO})"
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

    try:
        while True:
            t0 = time.perf_counter()
            z_addr = resolve_chain(handle, module_base, base_offset, chain_offsets)

            if z_addr == 0:
                print("[!] Pointer chain broken — waiting...", end="\r")
                time.sleep(1.0)
                continue

            status, internal_steer = run_tick(handle, z_addr, internal_steer)
            print(f"\r {status} ", end="", flush=True)

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
