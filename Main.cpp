#include "HWID.h"

NTSTATUS DriverEntry( const PDRIVER_OBJECT driverObject, const PUNICODE_STRING registryPath )
{
    HWID::ClearPropertyDriveSerials();
    HWID::ClearSMBIOS();
    HWID::SpoofMacAddresses();

    return STATUS_SUCCESS;
}