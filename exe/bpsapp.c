#include <windows.h>
#include <winioctl.h>
#include <stdlib.h>
#include <string.h>

#include "bpsdrv.h"


void __cdecl main(void)
{
    HANDLE DeviceHandle;
    ULONG BytesReturned;
    UCHAR DriverLocation[MAX_PATH]="";
    SC_HANDLE SCMHandle;
    SC_HANDLE ServiceHandle;
    SERVICE_STATUS ServiceStatus;
    char OutputBuffer[8];

    DeviceHandle=CreateFile(DEVICE_OPEN_NAME,GENERIC_READ|GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    
    if(INVALID_HANDLE_VALUE==DeviceHandle)
    {
        if(ERROR_FILE_NOT_FOUND!=GetLastError())
        {
            return;
        }

        GetCurrentDirectory(MAX_PATH,DriverLocation);
        strcat(DriverLocation,"\\");
        strcat(DriverLocation,DRIVER_NAME);
        strcat(DriverLocation,".sys");

        SCMHandle=OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);

        if(!SCMHandle)
        {
            return;
        }
        
        ServiceHandle=CreateService(SCMHandle,DRIVER_NAME,DRIVER_NAME,SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,SERVICE_ERROR_NORMAL,DriverLocation,NULL,NULL,NULL,NULL,NULL);

        if(!ServiceHandle)
        {
            if (ERROR_SERVICE_EXISTS!=GetLastError())
            {
                CloseServiceHandle(SCMHandle);
                return;
            }
            else
            {
                ServiceHandle=OpenService(SCMHandle,DRIVER_NAME,SERVICE_ALL_ACCESS);

                if (!ServiceHandle)
                {
                    CloseServiceHandle(SCMHandle);
                    return;
                }
            }
        }

        if (!StartService(ServiceHandle,0,NULL))
        {
            if (ERROR_SERVICE_ALREADY_RUNNING!=GetLastError())
            {
                DeleteService(ServiceHandle);
                CloseServiceHandle(ServiceHandle);
                CloseServiceHandle(SCMHandle);
                return;
            }
        }
        
        DeviceHandle=CreateFile(DEVICE_OPEN_NAME,GENERIC_READ|GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);

        if (INVALID_HANDLE_VALUE==DeviceHandle)
        {
            DeleteService(ServiceHandle);
            CloseServiceHandle(ServiceHandle);
            CloseServiceHandle(SCMHandle);      
            return;
        }
        
        CloseServiceHandle(ServiceHandle);
        CloseServiceHandle(SCMHandle);      
    }

    DeviceIoControl(DeviceHandle,(DWORD)IOCTL_DRIVER_METHOD_BUFFERED,&OutputBuffer,sizeof(OutputBuffer),&OutputBuffer,sizeof(OutputBuffer),&BytesReturned,NULL);

    CloseHandle(DeviceHandle);

    SCMHandle=OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);

    if(!SCMHandle)
    {
        return;
    }
        
    ServiceHandle=OpenService(SCMHandle,DRIVER_NAME,SERVICE_ALL_ACCESS);

    if (!ServiceHandle)
    {
        CloseServiceHandle(SCMHandle);
        return;
    }

    ControlService(ServiceHandle,SERVICE_CONTROL_STOP,&ServiceStatus);

    DeleteService(ServiceHandle);
    CloseServiceHandle(ServiceHandle);
    CloseServiceHandle(SCMHandle);
}
