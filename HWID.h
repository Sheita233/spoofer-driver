#pragma once

#include "NT.h"

namespace HWID {
    NTSTATUS ClearPropertyDriveSerials();
    NTSTATUS ClearSMBIOS();
    NTSTATUS SpoofMacAddresses();
    NTSTATUS SpoofRegistryIds();
    NTSTATUS SpoofVolumeSerials();
    NTSTATUS SpoofAll();
}