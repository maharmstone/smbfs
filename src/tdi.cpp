/* Copyright (c) Mark Harmstone 2019
 *
 * This file is part of SMBFS.
 *
 * SMBFS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public Licence as published by
 * the Free Software Foundation, either version 3 of the Licence, or
 * (at your option) any later version.
 *
 * SMBFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public Licence for more details.
 *
 * You should have received a copy of the GNU Lesser General Public Licence
 * along with SMBFS.  If not, see <http://www.gnu.org/licenses/>. */

#include "smbfs.h"
#include <tdikrnl.h>

static const WCHAR tdi_name[] = L"\\Device\\Tcp";

static NTSTATUS __stdcall irp_completion_routine(PDEVICE_OBJECT, PIRP, PVOID context) {
    auto event = (PKEVENT)context;

    KeSetEvent(event, IO_NETWORK_INCREMENT, false);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

void tdi::open_address_file() {
    OBJECT_ATTRIBUTES atts;
    UNICODE_STRING us;
    IO_STATUS_BLOCK iosb;
    char buf[sizeof(FILE_FULL_EA_INFORMATION) + TDI_TRANSPORT_ADDRESS_LENGTH + sizeof(TA_IP_ADDRESS) + 1];

    auto ea_info = reinterpret_cast<PFILE_FULL_EA_INFORMATION>(buf);

    RtlZeroMemory(buf, sizeof(buf));

    ea_info->EaNameLength = TDI_TRANSPORT_ADDRESS_LENGTH;

    RtlCopyMemory(ea_info->EaName, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH);

    ea_info->EaValueLength = sizeof(TA_IP_ADDRESS);

    auto addr = (PTA_IP_ADDRESS)(ea_info->EaName + TDI_TRANSPORT_ADDRESS_LENGTH + 1);

    addr->TAAddressCount = 1;
    addr->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    addr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;

    us.Length = us.MaximumLength = sizeof(tdi_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)tdi_name;

    InitializeObjectAttributes(&atts, &us, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    Status = ZwCreateFile(&address_handle, GENERIC_READ | GENERIC_WRITE, &atts, &iosb, 0, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, 0, buf, sizeof(buf));
    if (!NT_SUCCESS(Status)) {
        ERR("ZwCreateFile returned %08x\n", Status);
        return;
    }

    Status = ObReferenceObjectByHandle(address_handle, GENERIC_READ | GENERIC_WRITE, nullptr, KernelMode,
                                       (void**)&address_obj, nullptr);
    if (!NT_SUCCESS(Status)) {
        ERR("ObReferenceObjectByHandle returned %08x\n", Status);
        return;
    }
}

void tdi::open_connexion_file() {
    OBJECT_ATTRIBUTES atts;
    UNICODE_STRING us;
    IO_STATUS_BLOCK iosb;
    KEVENT event;
    PIRP Irp;
    char buf[sizeof(FILE_FULL_EA_INFORMATION) + TDI_CONNECTION_CONTEXT_LENGTH + sizeof(CONNECTION_CONTEXT) + 1];

    auto ea_info = reinterpret_cast<PFILE_FULL_EA_INFORMATION>(buf);

    RtlZeroMemory(buf, sizeof(buf));

    ea_info->EaNameLength = TDI_CONNECTION_CONTEXT_LENGTH;
    ea_info->EaValueLength = sizeof(CONNECTION_CONTEXT);

    RtlCopyMemory(ea_info->EaName, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH);

    // FIXME - set connexion context

    us.Length = us.MaximumLength = sizeof(tdi_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)tdi_name;

    InitializeObjectAttributes(&atts, &us, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    Status = ZwCreateFile(&conn_handle, GENERIC_READ | GENERIC_WRITE, &atts, &iosb, 0, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, 0, buf, sizeof(buf));
    if (!NT_SUCCESS(Status)) {
        ERR("ZwCreateFile returned %08x\n", Status);
        return;
    }

    Status = ObReferenceObjectByHandle(conn_handle, GENERIC_READ, nullptr, KernelMode, (void**)&conn_obj, nullptr);
    if (!NT_SUCCESS(Status)) {
        ERR("ObReferenceObjectByHandle returned %08x\n", Status);
        return;
    }

    conn_devobj = IoGetRelatedDeviceObject(conn_obj);

    KeInitializeEvent(&event, NotificationEvent, false);

    Irp = IoAllocateIrp(conn_devobj->StackSize, false);
    if (!Irp) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        return;
    }

    TdiBuildAssociateAddress(Irp, conn_devobj, conn_obj, irp_completion_routine, &event, address_handle);

    Status = IoCallDriver(conn_devobj, Irp);

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, false, nullptr);
        Status = Irp->IoStatus.Status;
    }

    if (!NT_SUCCESS(Status)) {
        ERR("associate Irp returned %08x\n", Status);
        IoFreeIrp(Irp);
        return;
    }

    IoFreeIrp(Irp);
}

void tdi::connect(uint32_t ip_address, uint16_t port) {
    PIRP Irp;
    KEVENT event;
    TDI_CONNECTION_INFORMATION request_info, return_info;
    TA_IP_ADDRESS addr, ret_addr;

    KeInitializeEvent(&event, NotificationEvent, false);

    Irp = IoAllocateIrp(conn_devobj->StackSize, false);
    if (!Irp) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        return;
    }

    RtlZeroMemory(&request_info, sizeof(request_info));
    RtlZeroMemory(&addr, sizeof(addr));

    request_info.RemoteAddressLength = sizeof(TA_IP_ADDRESS);
    request_info.RemoteAddress = &addr;

    addr.TAAddressCount = 1;
    addr.Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    addr.Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    addr.Address[0].Address[0].sin_port = WH2N(port);
    addr.Address[0].Address[0].in_addr = ip_address;

    RtlZeroMemory(&return_info, sizeof(return_info));
    RtlZeroMemory(&ret_addr, sizeof(ret_addr));

    return_info.RemoteAddressLength = sizeof(TA_IP_ADDRESS);
    return_info.RemoteAddress = &ret_addr;

    TdiBuildConnect(Irp, conn_devobj, conn_obj, irp_completion_routine, &event,
                    nullptr, &request_info, &return_info);

    Status = IoCallDriver(conn_devobj, Irp);

    if (Status == STATUS_PENDING) {
        LARGE_INTEGER timeout;

        timeout.QuadPart = -20000000; // 2 seconds

        if (KeWaitForSingleObject(&event, Executive, KernelMode, false, &timeout) == STATUS_TIMEOUT) {
            Status = STATUS_TIMEOUT;
            IoCancelIrp(Irp);
        } else
            Status = Irp->IoStatus.Status;
    }

    if (!NT_SUCCESS(Status)) {
        ERR("connect Irp returned %08x\n", Status);
        IoFreeIrp(Irp);
        return;
    }

    TRACE("Connected.\n"); // FIXME - print IP address and port

    IoFreeIrp(Irp);
}

tdi::tdi(uint32_t ip_address, uint16_t port) {
    open_address_file();

    if (!NT_SUCCESS(Status))
        return;

    open_connexion_file();

    if (!NT_SUCCESS(Status))
        return;

    connect(ip_address, port);

    if (!NT_SUCCESS(Status))
        return;

    init = true;
}

tdi::~tdi() {
    NTSTATUS Status;

    if (conn_obj) {
        Status = disconnect();
        if (!NT_SUCCESS(Status))
            ERR("tdi::disconnect returned %08x\n", Status);

        ObDereferenceObject(conn_obj);

        conn_obj = nullptr;
    }

    if (conn_handle) {
        ZwClose(conn_handle);
        conn_handle = nullptr;
    }

    if (address_obj) {
        ObDereferenceObject(address_obj);
        address_obj = nullptr;
    }

    if (address_handle) {
        ZwClose(address_handle);
        address_handle = nullptr;
    }

    init = false;
}

NTSTATUS tdi::send(void* data, ULONG data_len) {
    NTSTATUS Status;
    PIRP Irp;
    KEVENT event;
    PMDL mdl;

    KeInitializeEvent(&event, NotificationEvent, false);

    Irp = IoAllocateIrp(conn_devobj->StackSize, false);
    if (!Irp) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    mdl = IoAllocateMdl(data, data_len, false, false, nullptr);
    if (!mdl) {
        ERR("out of memory\n");
        IoFreeIrp(Irp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = STATUS_SUCCESS;

    _SEH2_TRY {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    } _SEH2_EXCEPT (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    } _SEH2_END;

    if (!NT_SUCCESS(Status)) {
        ERR("MmProbeAndLockPages returned %08x\n", Status);
        IoFreeMdl(mdl);
        IoFreeIrp(Irp);
        return Status;
    }

    TdiBuildSend(Irp, conn_devobj, conn_obj, irp_completion_routine, &event, mdl,
                 0, data_len);

    Status = IoCallDriver(conn_devobj, Irp);

    if (Status == STATUS_PENDING) {
        LARGE_INTEGER timeout;

        timeout.QuadPart = -30000000; // 3 seconds

        Status = KeWaitForSingleObject(&event, Executive, KernelMode, false, &timeout);

        if (Status == STATUS_TIMEOUT)
            IoCancelIrp(Irp);
        else
            Status = Irp->IoStatus.Status;
    }

    if (Status == STATUS_TIMEOUT) {
        ERR("send Irp timed out\n");
    } else if (!NT_SUCCESS(Status)) {
        ERR("send Irp returned %08x\n", Status);
    }

    MmUnlockPages(Irp->MdlAddress);
    IoFreeMdl(mdl);
    IoFreeIrp(Irp);

    return Status;
}

NTSTATUS tdi::recv(char* buf, ULONG buflen, PULONG retlen, PKEVENT event2) {
    NTSTATUS Status;
    PIRP Irp;
    KEVENT event;
    PMDL mdl;

    KeInitializeEvent(&event, NotificationEvent, false);

    Irp = IoAllocateIrp(conn_devobj->StackSize, false);
    if (!Irp) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    mdl = IoAllocateMdl((void*)buf, buflen, false, false, nullptr);
    if (!mdl) {
        ERR("out of memory\n");
        IoFreeIrp(Irp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = STATUS_SUCCESS;

    _SEH2_TRY {
        MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
    } _SEH2_EXCEPT (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    } _SEH2_END;

    if (!NT_SUCCESS(Status)) {
        ERR("MmProbeAndLockPages returned %08x\n", Status);
        IoFreeMdl(mdl);
        IoFreeIrp(Irp);
        return Status;
    }

    TdiBuildReceive(Irp, conn_devobj, conn_obj, irp_completion_routine, &event, mdl,
                    TDI_RECEIVE_NORMAL, buflen);

    Status = IoCallDriver(conn_devobj, Irp);


    if (Status == STATUS_PENDING) {
        void* objs[2];

        objs[0] = &event;
        objs[1] = event2;

        KeWaitForMultipleObjects(2, objs, WaitAny, Executive, KernelMode, false, nullptr, nullptr);

        if (KeReadStateEvent(event2)) {
            Status = STATUS_TIMEOUT;
            IoCancelIrp(Irp);
        } else
            Status = Irp->IoStatus.Status;
    }

    if (!NT_SUCCESS(Status))
        ERR("recv Irp returned %08x\n", Status);

    if (Status == STATUS_SUCCESS)
        *retlen = Irp->IoStatus.Information;

    MmUnlockPages(Irp->MdlAddress);
    IoFreeMdl(mdl);
    IoFreeIrp(Irp);

    return Status;
}

NTSTATUS tdi::disconnect() {
    NTSTATUS Status;
    PIRP Irp;
    KEVENT event;

    TRACE("disconnecting\n");

    KeInitializeEvent(&event, NotificationEvent, false);

    Irp = IoAllocateIrp(conn_devobj->StackSize, false);
    if (!Irp) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    TdiBuildDisconnect(Irp, conn_devobj, conn_obj, irp_completion_routine, &event, nullptr,
                       TDI_DISCONNECT_RELEASE, nullptr, nullptr);

    Status = IoCallDriver(conn_devobj, Irp);

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, false, nullptr);
        Status = Irp->IoStatus.Status;
    }

    if (!NT_SUCCESS(Status))
        ERR("disconnect Irp returned %08x\n", Status);

    IoFreeIrp(Irp);

    return Status;
}
