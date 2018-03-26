#include <windef.h>

#define IOCTL_DRIVER_METHOD_BUFFERED CTL_CODE(40000,0x902,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define DRIVER_NAME "bpsdrv"

#define NT_DEVICE_NAME L"\\Device\\BPSDRV"
#define DOS_DEVICE_NAME L"\\DosDevices\\BPSDRV"

#define DEVICE_OPEN_NAME "\\\\.\\BPSDRV"