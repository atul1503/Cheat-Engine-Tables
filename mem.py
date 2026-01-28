import ctypes
import struct
import sys
import os
import psutil
import json
from ctypes import wintypes

# Windows Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_GUARD = 0x100

# Comprehensive mask for readable memory
READABLE_ALL = 0xFE # Any combination of Read/Write/Execute except NoAccess/Guard
WRITABLE_ONLY = PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY

DATATYPES = {
    '1': ('int', 'i', 4),
    '2': ('float', 'f', 4),
    '3': ('double', 'd', 8),
    '4': ('long', 'q', 8),
    '5': ('short', 'h', 2),
    '6': ('byte', 'b', 1)
}

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def run_as_admin():
    if not is_admin():
        print("[!] Requesting Administrative Privileges...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

class MemoryScanner:
    def __init__(self):
        self.process_handle = None
        self.pid = None
        self.process_name = ""
        self.found_addresses = []
        self.current_datatype = DATATYPES['1']
        self.kernel32 = ctypes.windll.kernel32
        self.modules = []
        self.stop_requested = False
        self.active_filename = None

    def find_and_attach(self, name_substring):
        matches = [p.info for p in psutil.process_iter(['pid', 'name']) 
                   if name_substring.lower() in p.info['name'].lower()]
        if not matches: return print("[-] No process found.")
        
        target = matches[0] if len(matches) == 1 else matches[int(input("Select index: "))]
        self.pid, self.process_name = target['pid'], target['name']
        self.process_handle = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        
        if self.process_handle:
            print(f"[+] Attached to {self.process_name} (PID: {self.pid})")
            self.update_modules()
        else:
            print(f"[-] Failed. Error: {self.kernel32.GetLastError()}")

    def update_modules(self):
        self.modules = []
        print("\n" + "="*60)
        print(f"{'STATIC MODULE NAME':<30} | {'BASE ADDRESS':<14} | {'SIZE (KB)':<10}")
        print("-"*60)
        try:
            process = psutil.Process(self.pid)
            for m in process.memory_maps(grouped=False):
                if m.path:
                    name = os.path.basename(m.path)
                    base_addr = int(m.addr.split('-')[0], 16)
                    size_kb = m.rss // 1024
                    self.modules.append({
                        'name': name,
                        'base': base_addr,
                        'size': m.rss
                    })
                    print(f"{name[:30]:<30} | {hex(base_addr):<14} | {size_kb:<10}")
            self.modules.sort(key=lambda x: x['base'])
            print("="*60)
            print(f"[+] Total Static Modules: {len(self.modules)}\n")
        except Exception as e:
            print(f"[-] Could not list modules: {e}")

    def get_module_relative_addr(self, addr):
        for m in self.modules:
            if m['base'] <= addr < m['base'] + m['size']:
                return f"{m['name']} + {hex(addr - m['base'])}"
        return None

    def get_memory_regions(self, writable_only=True):
        regions = []
        addr = 0
        is_64bit = sys.maxsize > 2**32
        class MBI(ctypes.Structure):
            _fields_ = [("Base", ctypes.c_void_p), ("AllocBase", ctypes.c_void_p), ("AllocProt", ctypes.c_uint32),
                        ("PId", ctypes.c_uint16) if is_64bit else ("pad", ctypes.c_uint16),
                        ("Size", ctypes.c_size_t), ("State", ctypes.c_uint32), ("Prot", ctypes.c_uint32), ("Type", ctypes.c_uint32)]
        mbi = MBI()
        mask = WRITABLE_ONLY if writable_only else READABLE_ALL
        
        while self.kernel32.VirtualQueryEx(self.process_handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.State == MEM_COMMIT and (mbi.Prot & mask) and not (mbi.Prot & (PAGE_NOACCESS | PAGE_GUARD)):
                regions.append((mbi.Base, mbi.Size))
            addr += mbi.Size
        return regions

    def scan(self, value, is_filter=False):
        if not self.process_handle: return
        new_results = []
        fmt, size = self.current_datatype[1], self.current_datatype[2]
        search_bytes = struct.pack(fmt, value)

        if not is_filter:
            regions = self.get_memory_regions(writable_only=True)
            for idx, (base, r_size) in enumerate(regions):
                print(f"\r[*] Scanning: {idx+1}/{len(regions)} | Found: {len(new_results)}", end="", flush=True)
                buf = ctypes.create_string_buffer(r_size)
                if self.kernel32.ReadProcessMemory(self.process_handle, ctypes.c_void_p(base), buf, r_size, None):
                    data = buf.raw
                    offset = data.find(search_bytes)
                    while offset != -1:
                        new_results.append(base + offset)
                        offset = data.find(search_bytes, offset + 1)
        else:
            for addr in self.found_addresses:
                buf = ctypes.create_string_buffer(size)
                if self.kernel32.ReadProcessMemory(self.process_handle, ctypes.c_void_p(addr), buf, size, None):
                    try:
                        if struct.unpack(fmt, buf.raw)[0] == value:
                            new_results.append(addr)
                    except: pass
        
        self.found_addresses = new_results
        print(f"\n[+] Results: {len(self.found_addresses)}")

    def multi_level_pointer_scan(self, target_addr, max_offset=0x100, info=""):
        is_64bit = sys.maxsize > 2**32
        ptr_fmt, ptr_size = ('Q', 8) if is_64bit else ('I', 4)
        found = []
        regions = self.get_memory_regions(writable_only=False)
        
        for idx, (base, r_size) in enumerate(regions):
            if self.stop_requested: break
            print(f"\r[*] {info} Regions: {idx+1}/{len(regions)} | Hits: {len(found)}", end="", flush=True)
            buf = (ctypes.c_char * r_size)()
            if self.kernel32.ReadProcessMemory(self.process_handle, ctypes.c_void_p(base), buf, r_size, None):
                raw = bytes(buf)
                for i in range(0, r_size - ptr_size, 1): # Exhaustive 1-byte step
                    val = struct.unpack_from(ptr_fmt, raw, i)[0]
                    diff = target_addr - val
                    if 0 <= diff <= max_offset:
                        found.append((base + i, diff))
        return found

    def deep_pointer_scan(self, target_addr, depth=1, max_offset=0x100):
        self.stop_requested = False
        self.active_filename = f"ptr_{self.process_name}_{hex(target_addr)}.txt"
        current_targets = [(target_addr, [])]
        all_found_chains = [] # Store everything (static and dynamic)
        static_count = 0

        try:
            for d in range(depth):
                if self.stop_requested: break
                print(f"\n[*] Level {d+1}/{depth}...")
                next_targets = []
                for idx, (t_addr, chain) in enumerate(current_targets):
                    results = self.multi_level_pointer_scan(t_addr, max_offset, f"T: {idx+1}/{len(current_targets)}")
                    for ptr_addr, offset in results:
                        new_chain = [offset] + chain
                        next_targets.append((ptr_addr, new_chain))
                        
                        rel = self.get_module_relative_addr(ptr_addr)
                        entry = {
                            "base": rel if rel else hex(ptr_addr),
                            "is_static": True if rel else False,
                            "offsets": new_chain
                        }
                        all_found_chains.append(entry)
                        
                        if rel:
                            static_count += 1
                            print(f"\n    [!] STATIC FOUND: {rel} -> offsets {new_chain}")
                current_targets = next_targets
        except KeyboardInterrupt: self.stop_requested = True

        print(f"\n[+] Scan Complete. Total Paths Saved: {len(all_found_chains)}")
        print(f"[+] Static Paths Identified: {static_count}")
        
        if all_found_chains:
            with open(self.active_filename, "w") as f:
                json.dump(all_found_chains, f, indent=4)
            print(f"[+] All hits (static & dynamic) saved to {self.active_filename}")
        else:
            print("[-] No hits found.")

def main():
    run_as_admin()
    s = MemoryScanner()
    while True:
        try:
            print(f"\nTarget: {s.process_name or 'None'} | Results: {len(s.found_addresses)}")
            cmd = input("1. Attach | 2. New Scan | 3. Filter | 4. Deep Ptr Scan | 5. Reset | 6. Exit\n> ")
            if cmd == '1': s.find_and_attach(input("Name: "))
            elif cmd == '2' and s.pid:
                for k, v in DATATYPES.items(): print(f"{k}: {v[0]}")
                s.current_datatype = DATATYPES.get(input("Type: "), DATATYPES['1'])
                s.scan(float(input("Val: ")) if 'float' in s.current_datatype[0] else int(input("Val: ")))
            elif cmd == '3' and s.found_addresses:
                s.scan(float(input("Filter: ")) if 'float' in s.current_datatype[0] else int(input("Filter: ")), True)
            elif cmd == '4' and s.pid:
                addr = int(input("Target (hex): "), 16)
                depth = int(input("Depth (1-5): ") or "1")
                off = int(input("Max Offset (hex): ") or "100", 16)
                s.deep_pointer_scan(addr, depth, off)
            elif cmd == '5': s.found_addresses = []
            elif cmd == '6': break
        except KeyboardInterrupt: pass

if __name__ == "__main__": main()