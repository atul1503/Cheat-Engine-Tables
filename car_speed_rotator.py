"""
Car Speed Rotator + Drift Script — Forza Horizon 6
----------------------------------------------------
Two modes:
  python car_speed_rotator.py          → ROTATE mode (default)
  python car_speed_rotator.py drift    → DRIFT mode

Keyboard controls (work in both modes):
  LEFT  arrow → steer -= STEER_KEY_STEP  (turn left)
  RIGHT arrow → steer += STEER_KEY_STEP  (turn right)
  No key      → steer gradually returns to 0 (auto-center)

Run as Administrator.
"""

import ctypes
import ctypes.wintypes
import math
import struct
import sys
import time

# =============================================================================
# CONFIG — your actual values
# =============================================================================

PROCESS_NAME = "forzahorizon6.exe"

Z_SPEED_CHAIN = ("forzahorizon6.exe", 0xA994A50, [0x10, 0x10, -0x548])

X_SPEED_OFFSET = -8  # X is 2 floats before Z
Y_SPEED_OFFSET = -4  # Y is 1 float before Z
Z_SPEED_OFFSET = 0  # Z is at resolved address
STEER_OFFSET = 12  # steer is 3 floats after Z

# --- ROTATE mode ---
# Forza tuning: negative (inverted convention) and CE default divided by 1.1
STEER_SENSITIVITY = -0.03173  # radians per steer unit per tick (= -0.0349 / 1.1, Forza)
DEAD_ZONE = 0.0

# --- DRIFT mode ---
DRIFT_LATERAL_STRENGTH = 5.0
DRIFT_ROTATE_MIX = 0.03
DRIFT_SPEED_MIN = 2.0

# --- Keyboard steering ---
STEER_KEY_STEP = 0.1  # steer changes per tick while key held (CE-style)
STEER_DAMP = 1.1  # exponential decay divisor when no key pressed (Forza tuned)
STEER_MAX = 2.0  # max steer magnitude — prevents wind-up

# --- Speed boost/brake (per tick at 20Hz) ---
SPEED_BOOST_MULT = 1.01  # UP arrow: 1.01 per tick = +22% per second
SPEED_BRAKE_MULT = 0.97  # DOWN arrow: matches CE's accelFactor * 1.02 brake formula

UPDATE_HZ = 20  # CE-style 50ms ticks — gentler than 60Hz, gives game physics time

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


# =============================================================================
# Memory helpers
# =============================================================================


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
    buf = struct.pack("<f", value)
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
    """Non-blocking key state check using GetAsyncKeyState."""
    return bool(user32.GetAsyncKeyState(vk) & 0x8000)


def normalize_speed(new_vx, new_vz, original_speed):
    new_speed = math.sqrt(new_vx * new_vx + new_vz * new_vz)
    if new_speed > 0.001:
        scale = original_speed / new_speed
        return new_vx * scale, new_vz * scale
    return new_vx, new_vz


# =============================================================================
# Physics helpers
# =============================================================================


def rotate_xz(vx, vz, angle_rad):
    c, s = math.cos(angle_rad), math.sin(angle_rad)
    return vx * c - vz * s, vx * s + vz * c


def lateral_vector(vx, vz):
    speed = math.sqrt(vx * vx + vz * vz)
    if speed < 0.001:
        return 0.0, 0.0
    return -vz / speed, vx / speed


# =============================================================================
# Keyboard steer management
# =============================================================================


def apply_speed_keys(handle, z_addr, vx, vz):
    """UP = boost speed, DOWN = reduce speed."""
    up = key_down(VK_UP)
    down = key_down(VK_DOWN)
    if not up and not down:
        return vx, vz
    speed = math.sqrt(vx * vx + vz * vz)
    if speed < 0.001:
        return vx, vz
    mult = SPEED_BOOST_MULT if up else SPEED_BRAKE_MULT
    scale = (speed * mult) / speed
    return vx * scale, vz * scale


def update_keyboard_steer(current_steer):
    """
    Read LEFT/RIGHT keys and update steer value.
    LEFT  → steer - STEER_KEY_STEP
    RIGHT → steer + STEER_KEY_STEP
    None  → gradually return to 0
    """
    left = key_down(VK_LEFT)
    right = key_down(VK_RIGHT)

    if left and not right:
        new_steer = current_steer - STEER_KEY_STEP
    elif right and not left:
        new_steer = current_steer + STEER_KEY_STEP
    else:
        # Auto-center: exponential decay toward 0 (smooth fall-off, fast from large values)
        new_steer = current_steer / STEER_DAMP
        if abs(new_steer) < 0.001:
            new_steer = 0.0

    # Clamp to ±STEER_MAX — prevents wind-up
    if new_steer > STEER_MAX:
        new_steer = STEER_MAX
    if new_steer < -STEER_MAX:
        new_steer = -STEER_MAX
    return new_steer


# =============================================================================
# Modes
# =============================================================================


def run_rotate(handle, z_addr, steer):
    vx = read_float(handle, z_addr + X_SPEED_OFFSET)
    vz = read_float(handle, z_addr + Z_SPEED_OFFSET)
    original_speed = math.sqrt(vx * vx + vz * vz)

    if abs(steer) > DEAD_ZONE and original_speed > 0.1:
        angle = steer * STEER_SENSITIVITY
        new_vx, new_vz = rotate_xz(vx, vz, angle)
        new_vx, new_vz = normalize_speed(new_vx, new_vz, original_speed)
        write_float(handle, z_addr + X_SPEED_OFFSET, new_vx)
        write_float(handle, z_addr + Z_SPEED_OFFSET, new_vz)
        direction = "LEFT " if steer < 0 else "RIGHT"
        return (
            f"[ROTATE] steer={steer:+.3f} [{direction}]  "
            f"vx:{vx:+.2f}->{new_vx:+.2f}  vz:{vz:+.2f}->{new_vz:+.2f}  "
            f"speed={original_speed:.2f}"
        )
    return f"[ROTATE] steer={steer:+.3f} [--]  vx={vx:+.2f}  vz={vz:+.2f}  speed={original_speed:.2f}"


def run_drift(handle, z_addr, steer):
    vx = read_float(handle, z_addr + X_SPEED_OFFSET)
    vz = read_float(handle, z_addr + Z_SPEED_OFFSET)
    original_speed = math.sqrt(vx * vx + vz * vz)

    if abs(steer) > DEAD_ZONE and original_speed > DRIFT_SPEED_MIN:
        lat_x, lat_z = lateral_vector(vx, vz)
        lateral_amount = steer * DRIFT_LATERAL_STRENGTH
        new_vx = vx + lat_x * lateral_amount
        new_vz = vz + lat_z * lateral_amount
        if abs(DRIFT_ROTATE_MIX) > 0:
            new_vx, new_vz = rotate_xz(new_vx, new_vz, steer * DRIFT_ROTATE_MIX)
        new_vx, new_vz = normalize_speed(new_vx, new_vz, original_speed)
        write_float(handle, z_addr + X_SPEED_OFFSET, new_vx)
        write_float(handle, z_addr + Z_SPEED_OFFSET, new_vz)
        direction = "LEFT " if steer < 0 else "RIGHT"
        return (
            f"[DRIFT ] steer={steer:+.3f} [{direction}]  "
            f"lateral={lateral_amount:+.2f}  "
            f"vx:{vx:+.2f}->{new_vx:+.2f}  vz:{vz:+.2f}->{new_vz:+.2f}  "
            f"speed={original_speed:.2f}"
        )
    return f"[DRIFT ] steer={steer:+.3f} [--]  speed={original_speed:.2f}"


# =============================================================================
# Main
# =============================================================================


def main():
    mode = "drift" if len(sys.argv) > 1 and sys.argv[1].lower() == "drift" else "rotate"

    print(f"[*] Mode: {mode.upper()}")
    print(
        f"[*] Keys: LEFT/RIGHT = steer | UP = boost speed | DOWN = reduce speed | release = auto-center"
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
    steer = 0.0  # our keyboard-controlled steer value

    try:
        while True:
            t0 = time.perf_counter()

            z_addr = resolve_chain(handle, module_base, base_offset, chain_offsets)
            if z_addr == 0:
                print("[!] Pointer chain broken — waiting...", end="\r")
                time.sleep(1.0)
                continue

            # Update steer from keyboard
            steer = update_keyboard_steer(steer)

            # Write steer value to game memory
            write_float(handle, z_addr + STEER_OFFSET, steer)

            # Apply velocity modification
            if mode == "drift":
                status = run_drift(handle, z_addr, steer)
            else:
                status = run_rotate(handle, z_addr, steer)

            # UP/DOWN arrow: boost or reduce speed
            vx = read_float(handle, z_addr + X_SPEED_OFFSET)
            vz = read_float(handle, z_addr + Z_SPEED_OFFSET)
            new_vx, new_vz = apply_speed_keys(handle, z_addr, vx, vz)
            if new_vx != vx or new_vz != vz:
                write_float(handle, z_addr + X_SPEED_OFFSET, new_vx)
                write_float(handle, z_addr + Z_SPEED_OFFSET, new_vz)

            print(f"\r  {status}    ", end="", flush=True)

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
