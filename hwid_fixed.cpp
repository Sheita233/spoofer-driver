// ============================================================
//  HWID.cpp — Kernel HWID Spoofer — EAC/Fortnite ready
//  Windows 10/11 x64 — WDK/MSVC — KDMapper compatible
// ============================================================

#include "HWID.h"
#include "NT.h"
#include "util.h"
#include <ntdddisk.h>
#include <ntddndis.h>
#include <ntstrsafe.h>
#include <intrin.h>

#pragma pack(push, 1)

typedef struct _SMBIOS_HEADER {
    UCHAR Type; UCHAR Length; USHORT Handle;
} SMBIOS_HEADER, *PSMBIOS_HEADER;

typedef struct _SMBIOS_TYPE1 {
    SMBIOS_HEADER Header;
    UCHAR Manufacturer; UCHAR ProductName; UCHAR Version; UCHAR SerialNumber;
    UCHAR UUID[16]; UCHAR WakeUpType; UCHAR SKUNumber; UCHAR Family;
} SMBIOS_TYPE1, *PSMBIOS_TYPE1;

typedef struct _SMBIOS_TYPE2 {
    SMBIOS_HEADER Header;
    UCHAR Manufacturer; UCHAR Product; UCHAR Version; UCHAR SerialNumber;
    UCHAR AssetTag; UCHAR FeatureFlags; UCHAR LocationInChassis;
    USHORT ChassisHandle; UCHAR BoardType; UCHAR NumberOfContainedObjectHandles;
} SMBIOS_TYPE2, *PSMBIOS_TYPE2;

typedef struct _SMBIOS_TYPE3 {
    SMBIOS_HEADER Header;
    UCHAR Manufacturer; UCHAR Type; UCHAR Version; UCHAR SerialNumber;
    UCHAR AssetTag; UCHAR BootUpState; UCHAR PowerSupplyState;
    UCHAR ThermalState; UCHAR SecurityStatus; ULONG OEMDefined;
    UCHAR Height; UCHAR NumberOfPowerCords;
    UCHAR ContainedElementCount; UCHAR ContainedElementRecordLength;
} SMBIOS_TYPE3, *PSMBIOS_TYPE3;

typedef struct _SMBIOS_TYPE4 {
    SMBIOS_HEADER Header;
    UCHAR SocketDesignation; UCHAR ProcessorType; UCHAR ProcessorFamily;
    UCHAR ProcessorManufacturer; ULONG ProcessorID[2];
    UCHAR ProcessorVersion; UCHAR Voltage;
    USHORT ExternalClock; USHORT MaxSpeed; USHORT CurrentSpeed;
    UCHAR Status; UCHAR ProcessorUpgrade;
    USHORT L1CacheHandle; USHORT L2CacheHandle; USHORT L3CacheHandle;
    UCHAR SerialNumber; UCHAR AssetTag; UCHAR PartNumber;
    UCHAR CoreCount; UCHAR CoreEnabled; UCHAR ThreadCount;
    USHORT ProcessorCharacteristics; USHORT ProcessorFamily2;
    USHORT CoreCount2; USHORT CoreEnabled2; USHORT ThreadCount2;
} SMBIOS_TYPE4, *PSMBIOS_TYPE4;

typedef struct _SMBIOS_TYPE17 {
    SMBIOS_HEADER Header;
    USHORT PhysicalMemoryArrayHandle; USHORT MemoryErrorInformationHandle;
    USHORT TotalWidth; USHORT DataWidth; USHORT Size;
    UCHAR FormFactor; UCHAR DeviceSet; UCHAR DeviceLocator; UCHAR BankLocator;
    UCHAR MemoryType; USHORT TypeDetail; USHORT Speed;
    UCHAR Manufacturer; UCHAR SerialNumber; UCHAR AssetTag; UCHAR PartNumber;
    UCHAR Attributes; ULONG ExtendedSize; USHORT ConfiguredMemoryClockSpeed;
    USHORT MinimumVoltage; USHORT MaximumVoltage; USHORT ConfiguredVoltage;
    UCHAR MemoryTechnology; USHORT MemoryOperatingModeCapability;
    UCHAR FirmwareVersion; USHORT ModuleManufacturerID; USHORT ModuleProductID;
    USHORT MemorySubsystemControllerManufacturerID;
    USHORT MemorySubsystemControllerProductID;
    ULONG NonvolatileSize; ULONG VolatileSize; ULONG CacheSize;
    ULONG LogicalSize; ULONG ExtendedSpeed; ULONG ExtendedConfiguredMemorySpeed;
} SMBIOS_TYPE17, *PSMBIOS_TYPE17;

#pragma pack(pop)

// ─── CONFIG ──────────────────────────────────────────────────────────────────
#define HWID_BASE_SEED   0x5A5A1234UL   // change si tu veux une identité distincte
#define SPOOF_GPU        1
#define SPOOF_EXTRA_REG  1

// ─── RNG déterministe (LCG + seed par composant) ─────────────────────────────
static ULONG g_Seed = 0;

static ULONG NextRand() {
    g_Seed = g_Seed * 1103515245UL + 12345UL;
    return g_Seed;
}

static ULONG HashTag(const char* s) {
    ULONG h = 2166136261UL;
    while (*s) { h ^= (UCHAR)(*s++); h *= 16777619UL; }
    return h;
}

// chaque composant part d'un état indépendant -> valeurs stables et reproductibles
static void SeedFor(const char* tag) {
    g_Seed = HWID_BASE_SEED ^ HashTag(tag);
    NextRand();
}

static UCHAR RandomChar() {
    static const char cs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    return (UCHAR)cs[NextRand() % 36];
}

static void GenerateRandomString(char* buf, SIZE_T len) {
    if (!buf || len == 0) return;
    for (SIZE_T i = 0; i + 1 < len && i < 64; i++) buf[i] = (char)RandomChar();
    buf[len - 1] = '\0';
}

static void GenerateRandomUUID(UCHAR uuid[16]) {
    if (!uuid) return;
    for (int i = 0; i < 16; i++)
        uuid[i] = (UCHAR)(NextRand() ^ (NextRand() >> 8));
    uuid[6] = (uuid[6] & 0x0F) | 0x40;   // version 4
    uuid[8] = (uuid[8] & 0x3F) | 0x80;   // variant
}

// OUI constructeurs réels -> MAC crédible (bit unicast=0, global=0 déjà OK)
static const UCHAR g_MacOUIs[][3] = {
    { 0x00, 0x1B, 0x21 }, // Intel
    { 0x00, 0xE0, 0x4C }, // Realtek
    { 0x54, 0xBF, 0x64 }, // Dell
    { 0x00, 0x10, 0x18 }, // Broadcom
    { 0x00, 0x03, 0x7F }, // Atheros
    { 0x8C, 0x16, 0x45 }, // Intel
};

static void GenerateRealisticMac(UCHAR mac[6]) {
    UCHAR idx = (UCHAR)(NextRand() % (sizeof(g_MacOUIs) / sizeof(g_MacOUIs[0])));
    mac[0] = g_MacOUIs[idx][0];
    mac[1] = g_MacOUIs[idx][1];
    mac[2] = g_MacOUIs[idx][2];
    mac[3] = (UCHAR)NextRand();
    mac[4] = (UCHAR)NextRand();
    mac[5] = (UCHAR)NextRand();
}

// GUID format: {XXXXXXXX-XXXX-4XXX-XXXX-XXXXXXXXXXXX}
static void GenerateGuidString(WCHAR* buf, SIZE_T charCount) {
    if (!buf || charCount < 39) return;
    const WCHAR hex[] = L"0123456789ABCDEF";
    auto rndHex = [&]() -> WCHAR { return hex[NextRand() & 0xF]; };

    buf[0] = L'{';
    for (int i = 1;  i <= 8;  i++) buf[i] = rndHex();
    buf[9] = L'-';
    for (int i = 10; i <= 13; i++) buf[i] = rndHex();
    buf[14] = L'-';
    buf[15] = L'4';
    for (int i = 16; i <= 18; i++) buf[i] = rndHex();
    buf[19] = L'-';
    for (int i = 20; i <= 23; i++) buf[i] = rndHex();
    buf[24] = L'-';
    for (int i = 25; i <= 36; i++) buf[i] = rndHex();
    buf[37] = L'}';
    buf[38] = L'\0';
}

static void GenerateDriveSerial(char* buf, SIZE_T maxLen) {
    if (!buf || maxLen < 8) return;
    SIZE_T n = maxLen - 1;
    if (n > 20) n = 20;
    for (SIZE_T i = 0; i < n; i++) buf[i] = (char)RandomChar();
    buf[n] = '\0';
}

// ─── SMBIOS helpers ──────────────────────────────────────────────────────────
static char* SmbiosGetString(UCHAR* strSec, UCHAR idx, UCHAR* end) {
    if (idx == 0 || !strSec) return NULL;
    UCHAR* cur = strSec;
    for (UCHAR i = 1; i < idx; i++) {
        ULONG steps = 0;
        while (steps++ < 256 && cur < end) {
            if (!MmIsAddressValid(cur)) return NULL;
            if (*cur == 0) break;
            cur++;
        }
        if (cur >= end || !MmIsAddressValid(cur)) return NULL;
        cur++;
        if (!MmIsAddressValid(cur) || *cur == 0) return NULL;
    }
    return (cur < end && MmIsAddressValid(cur) && *cur) ? (char*)cur : NULL;
}

// écrase en place -> conserve la longueur d'origine du constructeur
static void SmbiosRandomizeString(char* s, UCHAR* end) {
    if (!s) return;
    for (int i = 0; i < 64; i++) {
        UCHAR* p = (UCHAR*)s + i;
        if (p >= end || !MmIsAddressValid(p)) break;
        if (*p == 0) break;
        *p = RandomChar();
    }
}

// ─── Registry helpers ────────────────────────────────────────────────────────
static NTSTATUS RegWriteRaw(
    LPCWSTR keyPath, LPCWSTR valueName, ULONG type,
    PVOID data, ULONG len, BOOLEAN create)
{
    UNICODE_STRING uPath, uName;
    RtlInitUnicodeString(&uPath, keyPath);
    RtlInitUnicodeString(&uName, valueName);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &uPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status;

    if (create) {
        ULONG disposition = 0;
        status = ZwCreateKey(&hKey, KEY_SET_VALUE | KEY_WRITE, &oa,
            0, NULL, REG_OPTION_NON_VOLATILE, &disposition);
    } else {
        status = ZwOpenKey(&hKey, KEY_SET_VALUE, &oa);
    }
    if (!NT_SUCCESS(status)) return status;

    status = ZwSetValueKey(hKey, &uName, 0, type, data, len);
    ZwClose(hKey);
    return status;
}

static NTSTATUS RegWriteString(LPCWSTR keyPath, LPCWSTR valueName, LPCWSTR data, BOOLEAN create) {
    SIZE_T len = 0;
    while (data[len]) len++;
    len = (len + 1) * sizeof(WCHAR);
    return RegWriteRaw(keyPath, valueName, REG_SZ, (PVOID)data, (ULONG)len, create);
}

static NTSTATUS RegWriteUtf16Binary(LPCWSTR keyPath, LPCWSTR valueName, LPCWSTR data, BOOLEAN create) {
    SIZE_T len = 0;
    while (data[len]) len++;
    len = (len + 1) * sizeof(WCHAR);
    return RegWriteRaw(keyPath, valueName, REG_BINARY, (PVOID)data, (ULONG)len, create);
}

// ─── MachineGuid + HwProfileGuid + MachineId + ComputerHardwareId ────────────
NTSTATUS HWID::SpoofRegistryIds() {
    DbgPrint("[HWID] SpoofRegistryIds()\n");
    SeedFor("reg");

    WCHAR guid1[39], guid2[39], guid3[39], guid4[39];
    GenerateGuidString(guid1, 39);
    GenerateGuidString(guid2, 39);
    GenerateGuidString(guid3, 39);
    GenerateGuidString(guid4, 39);

    WCHAR machineGuid[37];
    RtlCopyMemory(machineGuid, guid1 + 1, 36 * sizeof(WCHAR));
    machineGuid[36] = L'\0';

    NTSTATUS s1 = RegWriteString(
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography",
        L"MachineGuid", machineGuid, TRUE);
    DbgPrint("[HWID] MachineGuid: %08X\n", s1);

    NTSTATUS s2 = RegWriteString(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
        L"HwProfileGuid", guid2, TRUE);
    DbgPrint("[HWID] HwProfileGuid: %08X\n", s2);

#if SPOOF_EXTRA_REG
    NTSTATUS s3 = RegWriteString(
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\SQMClient",
        L"MachineId", guid3, TRUE);
    DbgPrint("[HWID] MachineId: %08X\n", s3);

    NTSTATUS s4 = RegWriteString(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
        L"ComputerHardwareId", guid4, TRUE);
    DbgPrint("[HWID] ComputerHardwareId: %08X\n", s4);
#endif

    return NT_SUCCESS(s1) ? s2 : s1;
}

// ─── GPU (niveau registre/WMI) ───────────────────────────────────────────────
#if SPOOF_GPU
static void SpoofGpuRegistry() {
    SeedFor("gpu");

    static const WCHAR* names[] = {
        L"NVIDIA GeForce RTX 3060",
        L"NVIDIA GeForce RTX 3070",
        L"NVIDIA GeForce GTX 1660 SUPER",
        L"AMD Radeon RX 6700 XT",
        L"AMD Radeon RX 580",
        L"Intel(R) UHD Graphics 630",
    };
    WCHAR desc[128];
    RtlStringCchCopyW(desc, 128, names[NextRand() % (sizeof(names) / sizeof(names[0]))]);

    for (int i = 0; i < 4; i++) {
        WCHAR path[256];
        RtlStringCchPrintfW(path, 256,
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
            L"{4d36e968-e325-11ce-bfc1-08002be10318}\\%04d", i);

        if (!NT_SUCCESS(RegWriteString(path, L"DriverDesc", desc, FALSE)))
            continue;

        RegWriteUtf16Binary(path, L"HardwareInformation.AdapterString", desc, FALSE);
        RegWriteUtf16Binary(path, L"HardwareInformation.ChipType",      desc, FALSE);
    }
    DbgPrint("[HWID] GPU registry spoofed\n");
}
#endif

// ─── Volume Serial (VPB->SerialNumber) ───────────────────────────────────────
NTSTATUS HWID::SpoofVolumeSerials() {
    DbgPrint("[HWID] SpoofVolumeSerials()\n");
    SeedFor("vol");

    ULONG spoofed = 0;

    auto patch = [&](PDEVICE_OBJECT d) {
        if (!MmIsAddressValid(d)) return;
        if (d->Vpb && MmIsAddressValid(d->Vpb)) {
            ULONG old = d->Vpb->SerialNumber;
            if (old != 0) {
                d->Vpb->SerialNumber = NextRand() ^ (NextRand() >> 16);
                DbgPrint("[HWID] VolumeSerial: %08X -> %08X\n", old, d->Vpb->SerialNumber);
                spoofed++;
            }
        }
    };

    const auto diskDriver = Nt::findDriverObjectByName(L"\\Driver\\Disk");
    if (diskDriver) {
        PDEVICE_OBJECT dev = diskDriver->DeviceObject;
        while (dev && MmIsAddressValid(dev)) {
            PDEVICE_OBJECT attached = dev;
            while (attached->AttachedDevice && MmIsAddressValid(attached->AttachedDevice))
                attached = attached->AttachedDevice;
            patch(attached);
            dev = dev->NextDevice;
        }
    }

    const auto volmgr = Nt::findDriverObjectByName(L"\\Driver\\volmgr");
    if (volmgr) {
        PDEVICE_OBJECT vdev = volmgr->DeviceObject;
        while (vdev && MmIsAddressValid(vdev)) {
            patch(vdev);
            vdev = vdev->NextDevice;
        }
    }

    DbgPrint("[HWID] VolumeSerials spoofed: %lu\n", spoofed);
    return STATUS_SUCCESS;
}

// ─── DISK serial (DeviceExtension storport) ──────────────────────────────────
NTSTATUS HWID::ClearPropertyDriveSerials() {
    DbgPrint("[HWID] ClearPropertyDriveSerials()\n");

    UCHAR serialNumberOffset = 0;
    ULONG_PTR storportBase = 0;
    SIZE_T    storportSize = 0;

    if (!NT_SUCCESS(Nt::findKernelModuleByName("storport.sys", &storportBase, &storportSize)) || !storportBase)
        return STATUS_NOT_FOUND;

    ULONG_PTR storportPage = 0;
    SIZE_T    storportPageSize = 0;
    Nt::findModuleSection(storportBase, "PAGE", &storportPage, &storportPageSize);

    if (storportPage) {
        const auto hit = SigScan::scanPattern(
            (UCHAR*)storportPage, storportPageSize,
            (char*)"\x66\x41\x3B\xF8\x72\xFF\x48\x8B\x53",
            (char*)"xxxxx?xxx");
        if (hit) serialNumberOffset = *(UCHAR*)((ULONG_PTR)hit + 0x9);
    }
    if (!serialNumberOffset) serialNumberOffset = 0x58;

    const auto diskDriver = Nt::findDriverObjectByName(L"\\Driver\\Disk");
    if (!diskDriver) return STATUS_NOT_FOUND;

    SeedFor("disk");
    PDEVICE_OBJECT cur = diskDriver->DeviceObject;

    while (cur) {
        if (!MmIsAddressValid(cur) || !cur->DeviceExtension) {
            cur = cur->NextDevice;
            continue;
        }
        ULONG_PTR ext = (ULONG_PTR)cur->DeviceExtension;

        PDEVICE_OBJECT phys = *(PDEVICE_OBJECT*)(ext + 0x200);
        if (!phys) phys = *(PDEVICE_OBJECT*)(ext + 0x10);

        if (phys && MmIsAddressValid(phys) && phys->DeviceExtension) {
            ULONG_PTR physExt = (ULONG_PTR)phys->DeviceExtension;
            PVOID* pp = (PVOID*)(physExt + serialNumberOffset);
            if (MmIsAddressValid(pp)) {
                char* serial = *(char**)pp;
                if (serial && MmIsAddressValid(serial))
                    GenerateDriveSerial(serial, 20);
            }
        }
        cur = cur->NextDevice;
    }

    DbgPrint("[HWID] Drive serials done\n");
    return STATUS_SUCCESS;
}

// ─── SMBIOS ──────────────────────────────────────────────────────────────────
NTSTATUS HWID::ClearSMBIOS() {
    DbgPrint("[HWID] ClearSMBIOS()\n");

    ULONG_PTR ntBase = 0;
    SIZE_T    ntSize = 0;
    if (!NT_SUCCESS(Nt::findKernelModuleByName("ntoskrnl.exe", &ntBase, &ntSize)) || !ntBase)
        return STATUS_NOT_FOUND;

    UCHAR* sig = (UCHAR*)SigScan::scanPattern((UCHAR*)ntBase, ntSize,
        (char*)"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15",
        (char*)"xxx????xxxx?xx");
    if (!sig)
        sig = (UCHAR*)SigScan::scanPattern((UCHAR*)ntBase, ntSize,
            (char*)"\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\x8B\x15",
            (char*)"xxx????xxxx?xx");

    if (!sig) { DbgPrint("[HWID] SMBIOS sig not found\n"); return STATUS_NOT_FOUND; }

    PPHYSICAL_ADDRESS physAddr = (PPHYSICAL_ADDRESS)(sig + 7 + *(LONG*)(sig + 3));
    if (!MmIsAddressValid(physAddr) || physAddr->QuadPart == 0)
        return STATUS_NOT_FOUND;

    ULONG tableSize = 0;
    {
        UCHAR* sigLen = (UCHAR*)SigScan::scanPattern((UCHAR*)ntBase, ntSize,
            (char*)"\x8B\x15\x00\x00\x00\x00\x48\x8B\x0D", (char*)"xx????xxx");
        if (sigLen) {
            PULONG pLen = (PULONG)(sigLen + 6 + *(LONG*)(sigLen + 2));
            if (MmIsAddressValid(pLen) && *pLen > 0 && *pLen <= 0x8000)
                tableSize = *pLen;
        }
    }
    if (tableSize == 0 || tableSize > 0x8000) tableSize = 0x2000;

    PVOID mapped = MmMapIoSpace(*physAddr, tableSize, MmNonCached);
    if (!mapped) return STATUS_INSUFFICIENT_RESOURCES;

    SeedFor("smbios");

    // ProcessorID = vrai CPUID(1) EDX:EBX -> cohérent avec le CPU réel
    int regs[4] = { 0, 0, 0, 0 };
    __cpuid(regs, 1);

    UCHAR* base = (UCHAR*)mapped;
    UCHAR* ptr  = base;
    UCHAR* end  = base + tableSize;
    int    count = 0;

    while (ptr + 4 <= end) {
        if (!MmIsAddressValid(ptr)) break;

        PSMBIOS_HEADER hdr = (PSMBIOS_HEADER)ptr;
        if (hdr->Type == 0x7F) break;
        if (hdr->Length < 4 || ptr + hdr->Length > end) break;

        UCHAR* strSec = ptr + hdr->Length;
        count++;

        switch (hdr->Type) {
        case 0x01:
            if (MmIsAddressValid(ptr + sizeof(SMBIOS_TYPE1) - 1)) {
                PSMBIOS_TYPE1 t = (PSMBIOS_TYPE1)ptr;
                GenerateRandomUUID(t->UUID);
                SmbiosRandomizeString(SmbiosGetString(strSec, t->SerialNumber, end), end);
                SmbiosRandomizeString(SmbiosGetString(strSec, t->SKUNumber,    end), end);
            }
            break;
        case 0x02:
            if (MmIsAddressValid(ptr + sizeof(SMBIOS_TYPE2) - 1)) {
                PSMBIOS_TYPE2 t = (PSMBIOS_TYPE2)ptr;
                SmbiosRandomizeString(SmbiosGetString(strSec, t->SerialNumber, end), end);
                SmbiosRandomizeString(SmbiosGetString(strSec, t->AssetTag,     end), end);
            }
            break;
        case 0x03:
            if (MmIsAddressValid(ptr + sizeof(SMBIOS_TYPE3) - 1)) {
                PSMBIOS_TYPE3 t = (PSMBIOS_TYPE3)ptr;
                SmbiosRandomizeString(SmbiosGetString(strSec, t->SerialNumber, end), end);
            }
            break;
        case 0x04:
            if (MmIsAddressValid(ptr + sizeof(SMBIOS_TYPE4) - 1)) {
                PSMBIOS_TYPE4 t = (PSMBIOS_TYPE4)ptr;
                t->ProcessorID[0] = (ULONG)regs[3]; // EDX
                t->ProcessorID[1] = (ULONG)regs[1]; // EBX
                SmbiosRandomizeString(SmbiosGetString(strSec, t->SerialNumber, end), end);
            }
            break;
        case 0x11:
            if (MmIsAddressValid(ptr + sizeof(SMBIOS_TYPE17) - 1)) {
                PSMBIOS_TYPE17 t = (PSMBIOS_TYPE17)ptr;
                SmbiosRandomizeString(SmbiosGetString(strSec, t->SerialNumber, end), end);
                SmbiosRandomizeString(SmbiosGetString(strSec, t->PartNumber,   end), end);
            }
            break;
        }

        ptr += hdr->Length;
        ULONG steps = 0;
        while (steps++ < 4096 && ptr + 1 < end) {
            if (!MmIsAddressValid(ptr)) goto smbios_done;
            if (ptr[0] == 0 && ptr[1] == 0) { ptr += 2; break; }
            ptr++;
        }
        if (steps >= 4096) break;
    }

smbios_done:
    DbgPrint("[HWID] SMBIOS done — %d structs\n", count);
    MmUnmapIoSpace(mapped, tableSize);
    return STATUS_SUCCESS;
}

// ─── MAC (NDIS) ──────────────────────────────────────────────────────────────
NTSTATUS HWID::SpoofMacAddresses() {
    DbgPrint("[HWID] SpoofMacAddresses()\n");

    RTL_OSVERSIONINFOW ver;
    RtlZeroMemory(&ver, sizeof(ver));
    ver.dwOSVersionInfoSize = sizeof(ver);
    RtlGetVersion(&ver);

    ULONG macOff = 0, permOff = 0;
    if      (ver.dwBuildNumber >= 26100) { macOff = 0x530; permOff = 0x528; }
    else if (ver.dwBuildNumber >= 25000) { macOff = 0x520; permOff = 0x518; }
    else if (ver.dwBuildNumber >= 22621) { macOff = 0x4D8; permOff = 0x4D0; }
    else if (ver.dwBuildNumber >= 22000) { macOff = 0x4C8; permOff = 0x4C0; }
    else if (ver.dwBuildNumber >= 19041) { macOff = 0x4B0; permOff = 0x4A8; }
    else if (ver.dwBuildNumber >= 18362) { macOff = 0x490; permOff = 0x488; }
    else                                 { macOff = 0x480; permOff = 0x478; }

    const auto ndisDriver = Nt::findDriverObjectByName(L"\\Driver\\ndis");
    if (!ndisDriver) return STATUS_NOT_FOUND;

    SeedFor("mac");
    ULONG spoofed = 0;

    PDEVICE_OBJECT dev = ndisDriver->DeviceObject;
    while (dev) {
        if (!MmIsAddressValid(dev)) break;
        if (!dev->DeviceExtension) { dev = dev->NextDevice; continue; }

        ULONG_PTR ext = (ULONG_PTR)dev->DeviceExtension;
        PUCHAR pCur  = (PUCHAR)(ext + macOff);
        PUCHAR pPerm = (PUCHAR)(ext + permOff);

        if (!MmIsAddressValid(pCur)  || !MmIsAddressValid(pCur  + 5) ||
            !MmIsAddressValid(pPerm) || !MmIsAddressValid(pPerm + 5)) {
            dev = dev->NextDevice; continue;
        }

        if (pCur[0] & 0x01) { dev = dev->NextDevice; continue; }   // multicast
        ULONG sum = 0;
        for (int i = 0; i < 6; i++) sum += pCur[i];
        if (sum == 0 || sum == 6 * 0xFF) { dev = dev->NextDevice; continue; }

        UCHAR nm[6];
        GenerateRealisticMac(nm);
        RtlCopyMemory(pCur,  nm, 6);
        RtlCopyMemory(pPerm, nm, 6);
        spoofed++;

        DbgPrint("[HWID] MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
            nm[0], nm[1], nm[2], nm[3], nm[4], nm[5]);

        dev = dev->NextDevice;
    }

    DbgPrint("[HWID] MACs spoofed: %lu\n", spoofed);
    return STATUS_SUCCESS;
}

// ─── ENTRY POINT ─────────────────────────────────────────────────────────────
NTSTATUS HWID::SpoofAll() {
    DbgPrint("========================================\n");
    DbgPrint("[HWID] SpoofAll()\n");
    DbgPrint("========================================\n");

    NTSTATUS s;
    s = ClearSMBIOS();               DbgPrint("[HWID] ClearSMBIOS: %08X\n", s);
    s = ClearPropertyDriveSerials(); DbgPrint("[HWID] DriveSerials: %08X\n", s);
    s = SpoofMacAddresses();         DbgPrint("[HWID] MAC: %08X\n", s);
    s = SpoofRegistryIds();          DbgPrint("[HWID] Registry: %08X\n", s);
    s = SpoofVolumeSerials();        DbgPrint("[HWID] VolumeSerials: %08X\n", s);
#if SPOOF_GPU
    SpoofGpuRegistry();
#endif

    DbgPrint("========================================\n");
    DbgPrint("[HWID] SpoofAll() done\n");
    DbgPrint("========================================\n");
    return STATUS_SUCCESS;
}

// ─── DriverEntry (SUPPRIME si tu en as déjà un ailleurs) ─────────────────────
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING) {
    return HWID::SpoofAll();
}
