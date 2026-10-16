// language: C++17 kernel, file: HWID.cpp, target: Windows 10-11 ring-0, WDK/MSVC
// KDMapper compatible — no IRP hook, direct memory + registry kernel spoof

#include "HWID.h"
#include "NT.h"
#include "util.h"
#include <ntdddisk.h>
#include <ntddndis.h>

#pragma pack(push, 1)

typedef struct _SMBIOS_HEADER {
    UCHAR Type;
    UCHAR Length;
    USHORT Handle;
} SMBIOS_HEADER, *PSMBIOS_HEADER;

typedef struct _SMBIOS_TYPE1 {
    SMBIOS_HEADER Header;
    UCHAR Manufacturer;
    UCHAR ProductName;
    UCHAR Version;
    UCHAR SerialNumber;
    UCHAR UUID[16];
    UCHAR WakeUpType;
    UCHAR SKUNumber;
    UCHAR Family;
} SMBIOS_TYPE1, *PSMBIOS_TYPE1;

typedef struct _SMBIOS_TYPE2 {
    SMBIOS_HEADER Header;
    UCHAR Manufacturer;
    UCHAR Product;
    UCHAR Version;
    UCHAR SerialNumber;
    UCHAR AssetTag;
    UCHAR FeatureFlags;
    UCHAR LocationInChassis;
    USHORT ChassisHandle;
    UCHAR BoardType;
    UCHAR NumberOfContainedObjectHandles;
} SMBIOS_TYPE2, *PSMBIOS_TYPE2;

typedef struct _SMBIOS_TYPE3 {
    SMBIOS_HEADER Header;
    UCHAR Manufacturer;
    UCHAR Type;
    UCHAR Version;
    UCHAR SerialNumber;
    UCHAR AssetTag;
    UCHAR BootUpState;
    UCHAR PowerSupplyState;
    UCHAR ThermalState;
    UCHAR SecurityStatus;
    ULONG OEMDefined;
    UCHAR Height;
    UCHAR NumberOfPowerCords;
    UCHAR ContainedElementCount;
    UCHAR ContainedElementRecordLength;
} SMBIOS_TYPE3, *PSMBIOS_TYPE3;

typedef struct _SMBIOS_TYPE4 {
    SMBIOS_HEADER Header;
    UCHAR SocketDesignation;
    UCHAR ProcessorType;
    UCHAR ProcessorFamily;
    UCHAR ProcessorManufacturer;
    ULONG ProcessorID[2];
    UCHAR ProcessorVersion;
    UCHAR Voltage;
    USHORT ExternalClock;
    USHORT MaxSpeed;
    USHORT CurrentSpeed;
    UCHAR Status;
    UCHAR ProcessorUpgrade;
    USHORT L1CacheHandle;
    USHORT L2CacheHandle;
    USHORT L3CacheHandle;
    UCHAR SerialNumber;
    UCHAR AssetTag;
    UCHAR PartNumber;
    UCHAR CoreCount;
    UCHAR CoreEnabled;
    UCHAR ThreadCount;
    USHORT ProcessorCharacteristics;
    USHORT ProcessorFamily2;
    USHORT CoreCount2;
    USHORT CoreEnabled2;
    USHORT ThreadCount2;
} SMBIOS_TYPE4, *PSMBIOS_TYPE4;

typedef struct _SMBIOS_TYPE17 {
    SMBIOS_HEADER Header;
    USHORT PhysicalMemoryArrayHandle;
    USHORT MemoryErrorInformationHandle;
    USHORT TotalWidth;
    USHORT DataWidth;
    USHORT Size;
    UCHAR FormFactor;
    UCHAR DeviceSet;
    UCHAR DeviceLocator;
    UCHAR BankLocator;
    UCHAR MemoryType;
    USHORT TypeDetail;
    USHORT Speed;
    UCHAR Manufacturer;
    UCHAR SerialNumber;
    UCHAR AssetTag;
    UCHAR PartNumber;
    UCHAR Attributes;
    ULONG ExtendedSize;
    USHORT ConfiguredMemoryClockSpeed;
    USHORT MinimumVoltage;
    USHORT MaximumVoltage;
    USHORT ConfiguredVoltage;
    UCHAR MemoryTechnology;
    USHORT MemoryOperatingModeCapability;
    UCHAR FirmwareVersion;
    USHORT ModuleManufacturerID;
    USHORT ModuleProductID;
    USHORT MemorySubsystemControllerManufacturerID;
    USHORT MemorySubsystemControllerProductID;
    ULONG NonvolatileSize;
    ULONG VolatileSize;
    ULONG CacheSize;
    ULONG LogicalSize;
    ULONG ExtendedSpeed;
    ULONG ExtendedConfiguredMemorySpeed;
} SMBIOS_TYPE17, *PSMBIOS_TYPE17;

#pragma pack(pop)

// ─── RNG ─────────────────────────────────────────────────────────────────────

static ULONG g_Seed = 0;

static void InitSeed() {
    LARGE_INTEGER t;
    KeQuerySystemTime(&t);
    g_Seed = (ULONG)(t.QuadPart ^ (ULONG_PTR)&t);
}

static UCHAR RandomChar() {
    g_Seed = g_Seed * 1103515245 + 12345;
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    return (UCHAR)charset[(g_Seed >> 16) % 36];
}

static void GenerateRandomString(char* buf, SIZE_T len) {
    if (!buf || len == 0) return;
    for (SIZE_T i = 0; i < len - 1 && i < 64; i++)
        buf[i] = (char)RandomChar();
    buf[len - 1] = '\0';
}

static void GenerateRandomUUID(UCHAR uuid[16]) {
    if (!uuid) return;
    for (int i = 0; i < 16; i++) {
        g_Seed = g_Seed * 1103515245 + 12345;
        uuid[i] = (UCHAR)(g_Seed ^ (g_Seed >> 8));
    }
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    uuid[8] = (uuid[8] & 0x3F) | 0x80;
}

static void GenerateRandomMac(UCHAR mac[6]) {
    for (int i = 0; i < 6; i++) {
        g_Seed = g_Seed * 1103515245 + 12345;
        mac[i] = (UCHAR)(g_Seed >> 16);
    }
    mac[0] = (mac[0] & 0xFE) | 0x02;
}

static void GenerateProcessorID(ULONG id[2]) {
    g_Seed = g_Seed * 1103515245 + 12345; id[0] = g_Seed;
    g_Seed = g_Seed * 1103515245 + 12345; id[1] = g_Seed;
}

static void GenerateDriveSerial(char* buf, SIZE_T maxLen) {
    if (!buf || maxLen < 8) return;
    SIZE_T slen = (maxLen >= 20) ? 20 : maxLen;
    GenerateRandomString(buf, slen);
    for (SIZE_T i = slen - 1; i < maxLen - 1; i++) buf[i] = ' ';
    if (maxLen > 0) buf[maxLen - 1] = '\0';
}

// GUID format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
static void GenerateGuidString(WCHAR* buf, SIZE_T charCount) {
    if (!buf || charCount < 39) return;
    const WCHAR hex[] = L"0123456789ABCDEF";
    auto rndHex = [&]() -> WCHAR {
        g_Seed = g_Seed * 1103515245 + 12345;
        return hex[(g_Seed >> 16) & 0xF];
    };
    // {XXXXXXXX-XXXX-4XXX-XXXX-XXXXXXXXXXXX}
    buf[0] = L'{';
    for (int i = 1;  i <= 8;  i++) buf[i] = rndHex();
    buf[9] = L'-';
    for (int i = 10; i <= 13; i++) buf[i] = rndHex();
    buf[14] = L'-';
    buf[15] = L'4'; // version 4
    for (int i = 16; i <= 18; i++) buf[i] = rndHex();
    buf[19] = L'-';
    for (int i = 20; i <= 23; i++) buf[i] = rndHex();
    buf[24] = L'-';
    for (int i = 25; i <= 36; i++) buf[i] = rndHex();
    buf[37] = L'}';
    buf[38] = L'\0';
}

// ─── SMBIOS helpers ───────────────────────────────────────────────────────────

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

static void SmbiosRandomizeString(char* s, UCHAR* end) {
    if (!s) return;
    for (int i = 0; i < 64; i++) {
        UCHAR* p = (UCHAR*)s + i;
        if (p >= end || !MmIsAddressValid(p)) break;
        if (*p == 0) break;
        *p = RandomChar();
    }
}

// ─── Registry kernel helper ───────────────────────────────────────────────────

static NTSTATUS RegWriteString(
    LPCWSTR keyPath,
    LPCWSTR valueName,
    LPCWSTR data)
{
    UNICODE_STRING uPath, uName;
    RtlInitUnicodeString(&uPath, keyPath);
    RtlInitUnicodeString(&uName, valueName);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &uPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey = NULL;
    ULONG disposition = 0;

    // ZwCreateKey au lieu de ZwOpenKey — crée si existe pas, ouvre si existe
    NTSTATUS status = ZwCreateKey(
        &hKey, KEY_SET_VALUE | KEY_WRITE,
        &oa, 0, NULL,
        REG_OPTION_NON_VOLATILE, &disposition);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[HWID] ZwCreateKey failed: %08X path: %ws\n", status, keyPath);
        return status;
    }

    SIZE_T dataLen = 0;
    const WCHAR* p = data;
    while (*p++) dataLen++;
    dataLen = (dataLen + 1) * sizeof(WCHAR);

    status = ZwSetValueKey(hKey, &uName, 0, REG_SZ,
        (PVOID)data, (ULONG)dataLen);

    if (!NT_SUCCESS(status))
        DbgPrint("[HWID] ZwSetValueKey failed: %08X\n", status);

    ZwClose(hKey);
    return status;
}

// ─── MachineGuid + HwProfileGuid ─────────────────────────────────────────────

NTSTATUS HWID::SpoofRegistryIds() {
    DbgPrint("[HWID] SpoofRegistryIds()\n");
    InitSeed();

    WCHAR guid1[39], guid2[39];
    GenerateGuidString(guid1, 39);
    GenerateGuidString(guid2, 39);

    // MachineGuid — sans accolades
    WCHAR machineGuid[37];
    RtlCopyMemory(machineGuid, guid1 + 1, 36 * sizeof(WCHAR));
    machineGuid[36] = L'\0';

    NTSTATUS s1 = RegWriteString(
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography",
        L"MachineGuid",
        machineGuid);
    DbgPrint("[HWID] MachineGuid: %08X -> %ws\n", s1, machineGuid);

    // HwProfileGuid — avec accolades
    NTSTATUS s2 = RegWriteString(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
        L"HwProfileGuid",
        guid2);
    DbgPrint("[HWID] HwProfileGuid: %08X -> %ws\n", s2, guid2);

    return NT_SUCCESS(s1) ? s2 : s1;
}

// ─── Volume Serial — patch NtQueryVolumeInformationFile en mémoire ───────────

NTSTATUS HWID::SpoofVolumeSerials() {
    DbgPrint("[HWID] SpoofVolumeSerials()\n");

    InitSeed();
    ULONG spoofed = 0;

    // Passe par \Driver\Disk -> VPB attaché à chaque device
    const auto diskDriver = Nt::findDriverObjectByName(L"\\Driver\\Disk");
    if (!diskDriver) {
        DbgPrint("[HWID] Disk driver not found\n");
        return STATUS_NOT_FOUND;
    }

    PDEVICE_OBJECT dev = diskDriver->DeviceObject;
    while (dev) {
        if (!MmIsAddressValid(dev)) break;

        // Remonte le device attaché pour trouver le VPB
        PDEVICE_OBJECT attached = dev;
        while (attached->AttachedDevice && MmIsAddressValid(attached->AttachedDevice))
            attached = attached->AttachedDevice;

        if (attached->Vpb && MmIsAddressValid(attached->Vpb)) {
            ULONG old = attached->Vpb->SerialNumber;
            if (old != 0) {
                g_Seed = g_Seed * 1103515245 + 12345;
                attached->Vpb->SerialNumber = g_Seed ^ (g_Seed >> 16);
                DbgPrint("[HWID] VolumeSerial: %08X -> %08X\n",
                    old, attached->Vpb->SerialNumber);
                spoofed++;
            }
        }

        dev = dev->NextDevice;
    }

    // Même chose via \Driver\volmgr
    const auto volmgr = Nt::findDriverObjectByName(L"\\Driver\\volmgr");
    if (volmgr) {
        PDEVICE_OBJECT vdev = volmgr->DeviceObject;
        while (vdev) {
            if (!MmIsAddressValid(vdev)) break;
            if (vdev->Vpb && MmIsAddressValid(vdev->Vpb)) {
                ULONG old = vdev->Vpb->SerialNumber;
                if (old != 0) {
                    g_Seed = g_Seed * 1103515245 + 12345;
                    vdev->Vpb->SerialNumber = g_Seed ^ (g_Seed >> 16);
                    DbgPrint("[HWID] VolmgrSerial: %08X -> %08X\n",
                        old, vdev->Vpb->SerialNumber);
                    spoofed++;
                }
            }
            vdev = vdev->NextDevice;
        }
    }

    DbgPrint("[HWID] VolumeSerials spoofed: %lu\n", spoofed);
    return STATUS_SUCCESS;
}

// ─── DISK — spoof direct DeviceExtension ─────────────────────────────────────

NTSTATUS HWID::ClearPropertyDriveSerials() {
    UCHAR serialNumberOffset = 0;

    ULONG_PTR storportBase = 0;
    SIZE_T    storportSize = 0;

    if (!NT_SUCCESS(Nt::findKernelModuleByName("storport.sys", &storportBase, &storportSize)) || !storportBase)
        return STATUS_NOT_FOUND;

    ULONG_PTR storportPage     = 0;
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

    InitSeed();
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

    DbgPrint("[HWID] ClearPropertyDriveSerials done\n");
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

    if (!sig) {
        sig = (UCHAR*)SigScan::scanPattern((UCHAR*)ntBase, ntSize,
            (char*)"\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\x8B\x15",
            (char*)"xxx????xxxx?xx");
    }

    if (!sig) { DbgPrint("[HWID] SMBIOS sig not found\n"); return STATUS_NOT_FOUND; }

    PPHYSICAL_ADDRESS physAddr = (PPHYSICAL_ADDRESS)(sig + 7 + *(LONG*)(sig + 3));

    if (!MmIsAddressValid(physAddr) || physAddr->QuadPart == 0) {
        DbgPrint("[HWID] physAddr invalid\n");
        return STATUS_NOT_FOUND;
    }

    ULONG tableSize = 0;
    {
        UCHAR* sigLen = (UCHAR*)SigScan::scanPattern((UCHAR*)ntBase, ntSize,
            (char*)"\x8B\x15\x00\x00\x00\x00\x48\x8B\x0D",
            (char*)"xx????xxx");
        if (sigLen) {
            PULONG pLen = (PULONG)(sigLen + 6 + *(LONG*)(sigLen + 2));
            if (MmIsAddressValid(pLen) && *pLen > 0 && *pLen <= 0x8000)
                tableSize = *pLen;
        }
    }
    if (tableSize == 0 || tableSize > 0x8000) tableSize = 0x2000;

    DbgPrint("[HWID] SMBIOS phys=%llx size=%lu\n", physAddr->QuadPart, tableSize);

    PVOID mapped = MmMapIoSpace(*physAddr, tableSize, MmNonCached);
    if (!mapped) { DbgPrint("[HWID] MmMapIoSpace failed\n"); return STATUS_INSUFFICIENT_RESOURCES; }

    InitSeed();

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
                DbgPrint("[HWID] Type1 patched\n");
            }
            break;
        case 0x02:
            if (MmIsAddressValid(ptr + sizeof(SMBIOS_TYPE2) - 1)) {
                PSMBIOS_TYPE2 t = (PSMBIOS_TYPE2)ptr;
                SmbiosRandomizeString(SmbiosGetString(strSec, t->SerialNumber, end), end);
                SmbiosRandomizeString(SmbiosGetString(strSec, t->AssetTag,     end), end);
                DbgPrint("[HWID] Type2 patched\n");
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
                GenerateProcessorID(t->ProcessorID);
                SmbiosRandomizeString(SmbiosGetString(strSec, t->SerialNumber, end), end);
                DbgPrint("[HWID] Type4 patched\n");
            }
            break;
        case 0x11:
            if (MmIsAddressValid(ptr + sizeof(SMBIOS_TYPE17) - 1)) {
                PSMBIOS_TYPE17 t = (PSMBIOS_TYPE17)ptr;
                SmbiosRandomizeString(SmbiosGetString(strSec, t->SerialNumber, end), end);
                SmbiosRandomizeString(SmbiosGetString(strSec, t->PartNumber,   end), end);
                DbgPrint("[HWID] Type17 patched\n");
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

// ─── MAC ─────────────────────────────────────────────────────────────────────

NTSTATUS HWID::SpoofMacAddresses() {
    DbgPrint("[HWID] SpoofMacAddresses()\n");

    RTL_OSVERSIONINFOW ver;
    RtlZeroMemory(&ver, sizeof(ver));
    ver.dwOSVersionInfoSize = sizeof(ver);
    RtlGetVersion(&ver);

    ULONG macOff  = 0;
    ULONG permOff = 0;

    if      (ver.dwBuildNumber >= 26100) { macOff = 0x530; permOff = 0x528; }
    else if (ver.dwBuildNumber >= 25000) { macOff = 0x520; permOff = 0x518; }
    else if (ver.dwBuildNumber >= 22621) { macOff = 0x4D8; permOff = 0x4D0; }
    else if (ver.dwBuildNumber >= 22000) { macOff = 0x4C8; permOff = 0x4C0; }
    else if (ver.dwBuildNumber >= 19041) { macOff = 0x4B0; permOff = 0x4A8; }
    else if (ver.dwBuildNumber >= 18362) { macOff = 0x490; permOff = 0x488; }
    else                                 { macOff = 0x480; permOff = 0x478; }

    const auto ndisDriver = Nt::findDriverObjectByName(L"\\Driver\\ndis");
    if (!ndisDriver) return STATUS_NOT_FOUND;

    InitSeed();
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

        if (pCur[0] & 0x01) { dev = dev->NextDevice; continue; }
        ULONG sum = 0;
        for (int i = 0; i < 6; i++) sum += pCur[i];
        if (sum == 0 || sum == 6 * 0xFF) { dev = dev->NextDevice; continue; }

        UCHAR nm[6];
        GenerateRandomMac(nm);
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

    InitSeed();

    NTSTATUS s;

    s = ClearSMBIOS();
    DbgPrint("[HWID] ClearSMBIOS: %08X\n", s);

    s = ClearPropertyDriveSerials();
    DbgPrint("[HWID] ClearPropertyDriveSerials: %08X\n", s);

    s = SpoofMacAddresses();
    DbgPrint("[HWID] SpoofMacAddresses: %08X\n", s);

    s = SpoofRegistryIds();
    DbgPrint("[HWID] SpoofRegistryIds: %08X\n", s);

    s = SpoofVolumeSerials();
    DbgPrint("[HWID] SpoofVolumeSerials: %08X\n", s);

    DbgPrint("========================================\n");
    DbgPrint("[HWID] SpoofAll() done\n");
    DbgPrint("========================================\n");

    return STATUS_SUCCESS;
}