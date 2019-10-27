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
#include <stddef.h>
#include <windef.h>
#include <nb30.h>

#ifdef _DEBUG
serial_logger* logger = nullptr;
#endif

PDRIVER_OBJECT drvobj;
ERESOURCE connexion_lock;
LIST_ENTRY connexion_list;
bool shutting_down = false;
PDEVICE_OBJECT master_devobj = nullptr;
HANDLE mup_handle = nullptr;
HANDLE connexion_reap_thread_handle = nullptr;
KEVENT connexion_reap_thread_quit_event;
KEVENT driver_unload_event;

// #define NAME_TESTING

unsigned int debug_log_level = 2;

#define IOCTL_SMBFS_UNLOAD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x5ab, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

static const int64_t CONNEXION_REAP_THREAD_INTERVAL = 10; // connexion reap thread should run every 10 seconds
static const int64_t CONNEXION_AGE = 30; // number of seconds before inactive connexion gets reaped

static const WCHAR device_name[] = L"\\Device\\smbfs";

static void __stdcall DriverUnload(PDRIVER_OBJECT) {
    TRACE("\n");

    shutting_down = true;

    KeSetEvent(&driver_unload_event, 0, false);

    if (connexion_reap_thread_handle)
        KeWaitForSingleObject(&connexion_reap_thread_quit_event, Executive, KernelMode, false, nullptr);

    ExAcquireResourceExclusiveLite(&connexion_lock, true);

    while (!IsListEmpty(&connexion_list)) {
        auto conn = CONTAINING_RECORD(RemoveHeadList(&connexion_list), smb_connexion, list_entry);

        conn->smb_connexion::~smb_connexion();
        ExFreePool(conn);
    }

    ExReleaseResourceLite(&connexion_lock);

    if (mup_handle)
        FsRtlDeregisterUncProvider(mup_handle);

    ExDeleteResourceLite(&connexion_lock);

    IoDeleteDevice(master_devobj);

#ifdef _DEBUG
    if (logger)
        delete logger;
#endif
}

#define IOCTL_NETBT_LOOKUP_NAME _TDI_CONTROL_CODE(0x25, METHOD_OUT_DIRECT)

typedef struct _NETBT_LOOKUP_IN {
    ULONG unknown1;
    ULONG unknown2;
    char hostname[16];
} NETBT_LOOKUP_IN, *PNETBT_LOOKUP_IN;

typedef struct _NETBT_LOOKUP_OUT {
    FIND_NAME_HEADER Header;
    FIND_NAME_BUFFER Buffer;
} NETBT_LOOKUP_OUT, *PNETBT_LOOKUP_OUT;

typedef struct {
    LIST_ENTRY list_entry;
    PFILE_OBJECT fileobj;
    PDEVICE_OBJECT devobj;
    NETBT_LOOKUP_OUT out;
    KEVENT event;
    IO_STATUS_BLOCK iosb;
    NTSTATUS Status;
} netbt_entry;

static NTSTATUS find_netbt_entries(LIST_ENTRY* netbt_entries) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING netkeyus;

    static const WCHAR prefix[] = L"\\Device\\NetBT_Tcpip_";

    // Registry key for network connexions
    static const WCHAR netkey[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}";

    netkeyus.Buffer = (WCHAR*)netkey;
    netkeyus.Length = netkeyus.MaximumLength = sizeof(netkey) - sizeof(WCHAR);

    InitializeObjectAttributes(&oa, &netkeyus, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

    Status = ZwOpenKey(&h, KEY_READ, &oa);
    if (!NT_SUCCESS(Status)) {
        ERR("ZwOpenKey returned %08x\n", Status);
        return Status;
    }

    ULONG kbilen = offsetof(KEY_BASIC_INFORMATION, Name[0]) + (50 * sizeof(WCHAR));
    ULONG retlen, index = 0;
    auto kbi = (KEY_BASIC_INFORMATION*)ExAllocatePoolWithTag(PagedPool, kbilen, ALLOC_TAG);

    if (!kbi) {
        ERR("out of memory\n");
        ZwClose(h);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    do {
        Status = ZwEnumerateKey(h, index, KeyBasicInformation, kbi, kbilen, &retlen);

        if (Status == STATUS_NO_MORE_ENTRIES)
            break;

        if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW) {
            ERR("ZwEnumerateKey returned %08x\n", Status);
            ExFreePool(kbi);
            ZwClose(h);
            return Status;
        }

        if (kbi->NameLength == 38 * sizeof(WCHAR)) {
            WCHAR name[sizeof(prefix) - sizeof(WCHAR) + (38 * sizeof(WCHAR))];
            UNICODE_STRING nameus;
            PFILE_OBJECT fileobj;
            PDEVICE_OBJECT devobj;

            TRACE("key: %.*S\n", kbi->NameLength / sizeof(WCHAR), kbi->Name);

            RtlCopyMemory(name, prefix, sizeof(prefix) - sizeof(WCHAR));
            RtlCopyMemory((uint8_t*)name + sizeof(prefix) - sizeof(WCHAR), kbi->Name, kbi->NameLength);

            nameus.Buffer = name;
            nameus.Length = nameus.MaximumLength = (USHORT)(sizeof(prefix) - sizeof(WCHAR) + kbi->NameLength);

            Status = IoGetDeviceObjectPointer(&nameus, FILE_READ_ATTRIBUTES, &fileobj, &devobj);
            if (NT_SUCCESS(Status)) {
                auto entry = (netbt_entry*)ExAllocatePoolWithTag(NonPagedPool, sizeof(netbt_entry), ALLOC_TAG);
                if (!entry) {
                    ObDereferenceObject(fileobj);
                    ExFreePool(kbi);
                    ZwClose(h);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                entry->fileobj = fileobj;
                entry->devobj = devobj;
                InsertTailList(netbt_entries, &entry->list_entry);
            }
        }


        index++;
    } while (true);

    ExFreePool(kbi);

    ZwClose(h);

    return STATUS_SUCCESS;
}

static NTSTATUS netbios_lookup(PCUNICODE_STRING hostname, uint32_t* ip_address) {
    NTSTATUS Status;
    NETBT_LOOKUP_IN in;
    LIST_ENTRY netbt_entries;
    LIST_ENTRY* le;
    bool found = false;

    InitializeListHead(&netbt_entries);

    Status = find_netbt_entries(&netbt_entries);
    if (!NT_SUCCESS(Status)) {
        ERR("find_netbt_entries returned %08x\n", Status);

        while (!IsListEmpty(&netbt_entries)) {
            auto ent = CONTAINING_RECORD(RemoveHeadList(&netbt_entries), netbt_entry, list_entry);

            ObDereferenceObject(ent->fileobj);

            ExFreePool(ent);
        }

        return Status;
    }

    if (IsListEmpty(&netbt_entries))
        return STATUS_NOT_FOUND;

    for (unsigned int i = 0; i < 15; i++) {
        if (i < hostname->Length / sizeof(WCHAR)) {
            if (hostname->Buffer[i] >= 0x100)
                return STATUS_NOT_FOUND; // not allowing Unicode

            if (hostname->Buffer[i] >= 'a' && hostname->Buffer[i] <= 'z')
                in.hostname[i] = (char)(hostname->Buffer[i] + 'A' - 'a');
            else
                in.hostname[i] = (char)hostname->Buffer[i];
        } else
            in.hostname[i] = ' ';
    }

    in.hostname[15] = 0;

    in.unknown1 = 0;
    in.unknown2 = 0;

    le = netbt_entries.Flink;
    while (le != &netbt_entries) {
        auto ent = CONTAINING_RECORD(le, netbt_entry, list_entry);

        KeInitializeEvent(&ent->event, NotificationEvent, false);

        PIRP Irp = IoBuildDeviceIoControlRequest(IOCTL_NETBT_LOOKUP_NAME, ent->devobj, &in, sizeof(in),
                                                 &ent->out, sizeof(ent->out), false, &ent->event, &ent->iosb);
        if (!Irp) {
            ERR("IoBuildDeviceIoControlRequest returned %08x\n", Status);
            ent->Status = STATUS_INSUFFICIENT_RESOURCES;
        } else
            ent->Status = IoCallDriver(ent->devobj, Irp);

        le = le->Flink;
    }

    le = netbt_entries.Flink;
    while (le != &netbt_entries) {
        auto ent = CONTAINING_RECORD(le, netbt_entry, list_entry);

        if (ent->Status == STATUS_PENDING) {
            KeWaitForSingleObject(&ent->event, Executive, KernelMode, false, nullptr);
            ent->Status = ent->iosb.Status;
        }

        le = le->Flink;
    }

    le = netbt_entries.Flink;
    while (le != &netbt_entries) {
        auto ent = CONTAINING_RECORD(le, netbt_entry, list_entry);

        if (NT_SUCCESS(ent->Status) && ent->out.Header.node_count > 0) {
            *ip_address = *(uint32_t*)&ent->out.Buffer.source_addr[2];
            found = true;
        }

        le = le->Flink;
    }

    while (!IsListEmpty(&netbt_entries)) {
        auto ent = CONTAINING_RECORD(RemoveHeadList(&netbt_entries), netbt_entry, list_entry);

        ObDereferenceObject(ent->fileobj);

        ExFreePool(ent);
    }

    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

static NTSTATUS resolve_hostname(PCUNICODE_STRING hostname2, uint32_t* ip_address) {
    NTSTATUS Status;
    bool is_ip;
    uint32_t ipv4;
    unsigned int ip_bit, num_ip_bits;
    PCUNICODE_STRING hostname;

#ifdef NAME_TESTING
    UNICODE_STRING hostnamemod;

    // TESTING
    if (hostname2->Length < 4 * sizeof(WCHAR) ||
        (hostname2->Buffer[0] != 'T' && hostname2->Buffer[0] != 't') ||
        (hostname2->Buffer[1] != 'E' && hostname2->Buffer[1] != 'e') ||
        (hostname2->Buffer[2] != 'S' && hostname2->Buffer[2] != 's') ||
        (hostname2->Buffer[3] != 'T' && hostname2->Buffer[3] != 't'))
        return STATUS_NOT_FOUND;

    hostnamemod.Buffer = &hostname2->Buffer[4];
    hostnamemod.Length = hostname2->Length - (4 * sizeof(WCHAR));
    hostnamemod.MaximumLength = hostname2->MaximumLength - (4 * sizeof(WCHAR));
    hostname = &hostnamemod;
#else
    hostname = hostname2;
#endif

    is_ip = true;
    ip_bit = 0;
    ipv4 = 0;
    num_ip_bits = 0;

    for (unsigned int i = 0; i < hostname->Length / sizeof(WCHAR); i++) {
        if (hostname->Buffer[i] >= '0' && hostname->Buffer[i] <= '9') {
            ip_bit *= 10;
            ip_bit += hostname->Buffer[i] - '0';

            if (ip_bit > 255) {
                is_ip = false;
                break;
            }
        } else if (hostname->Buffer[i] == '.' && (i > 0 && hostname->Buffer[i-1] != '.')) {
            num_ip_bits++;

            if (num_ip_bits == 4) {
                is_ip = false;
                break;
            }

            ipv4 <<= 8;
            ipv4 |= ip_bit;
            ip_bit = 0;
        } else {
            is_ip = false;
            break;
        }
    }

    if (is_ip && num_ip_bits != 3)
        is_ip = false;

    if (is_ip) {
        ipv4 <<= 8;
        ipv4 |= ip_bit;

        *ip_address = _byteswap_ulong(ipv4);
        return STATUS_SUCCESS;
    }

    Status = netbios_lookup(hostname, ip_address);

    if (!NT_SUCCESS(Status)) {
        ERR("netbios_lookup returned %08x\n", Status);
    } else
        return STATUS_SUCCESS;

    // FIXME - do DNS?

    return STATUS_NOT_FOUND;
}

static NTSTATUS add_connexion(PUNICODE_STRING hostname, smb_connexion** c) {
    NTSTATUS Status;
    uint32_t ip_address;

    if (shutting_down)
        return STATUS_TOO_LATE;

    // search by hostname

    ExAcquireResourceSharedLite(&connexion_lock, true);

    {
        LIST_ENTRY* le = connexion_list.Flink;

        while (le != &connexion_list) {
            auto conn = CONTAINING_RECORD(le, smb_connexion, list_entry);

            if (!RtlCompareUnicodeString(hostname, &conn->hostname, true)) {
                InterlockedIncrement(&conn->refcount);
                *c = conn;
                ExReleaseResourceLite(&connexion_lock);

                return STATUS_SUCCESS;
            }

            le = le->Flink;
        }
    }

    ExReleaseResourceLite(&connexion_lock);

    // resolve hostname

    Status = resolve_hostname(hostname, &ip_address);
    if (!NT_SUCCESS(Status)) {
        ERR("resolve_hostname returned %08x\n", Status);
        return Status;
    }

    // search by IP address

    ExAcquireResourceSharedLite(&connexion_lock, true);

    {
        LIST_ENTRY* le = connexion_list.Flink;

        while (le != &connexion_list) {
            auto conn = CONTAINING_RECORD(le, smb_connexion, list_entry);

            if (conn->ip_address == ip_address) {
                InterlockedIncrement(&conn->refcount);
                *c = conn;
                ExReleaseResourceLite(&connexion_lock);

                return STATUS_SUCCESS;
            }

            le = le->Flink;
        }
    }

    ExReleaseResourceLite(&connexion_lock);

    // FIXME - faster if we create object outside of lock, then delete if duplicate

    ExAcquireResourceExclusiveLite(&connexion_lock, true);

    if (shutting_down) {
        ExReleaseResourceLite(&connexion_lock);
        return STATUS_TOO_LATE;
    }

    // check again
    {
        LIST_ENTRY* le = connexion_list.Flink;

        while (le != &connexion_list) {
            auto conn = CONTAINING_RECORD(le, smb_connexion, list_entry);

            if (conn->ip_address == ip_address) {
                InterlockedIncrement(&conn->refcount);
                *c = conn;
                ExReleaseResourceLite(&connexion_lock);

                return STATUS_SUCCESS;
            }

            le = le->Flink;
        }
    }

    auto conn = (smb_connexion*)ExAllocatePoolWithTag(NonPagedPool, sizeof(smb_connexion), ALLOC_TAG);
    if (!conn) {
        ERR("out of memory\n");
        ExReleaseResourceLite(&connexion_lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    new (conn) smb_connexion(hostname, ip_address);

    if (!NT_SUCCESS(conn->Status)) {
        NTSTATUS Status = conn->Status;

        ERR("smb_connexion::smb_connexion returned %08x\n", conn->Status);
        ExReleaseResourceLite(&connexion_lock);
        conn->smb_connexion::~smb_connexion();
        ExFreePool(conn);
        return Status;
    }

    InsertTailList(&connexion_list, &conn->list_entry);

    *c = conn;

    ExReleaseResourceLite(&connexion_lock);

    return STATUS_SUCCESS;
}

static bool is_top_level(PIRP Irp) {
    if (!IoGetTopLevelIrp()) {
        IoSetTopLevelIrp(Irp);
        return true;
    }

    return false;
}

static NTSTATUS create_file(PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    UNICODE_STRING hostname, filename;
    smb_connexion* conn;

    if (IrpSp->FileObject->FileName.Buffer[0] != '\\') {
        WARN("filename did not begin with a backslash\n");
        return STATUS_OBJECT_PATH_NOT_FOUND;
    }

    hostname.Buffer = &IrpSp->FileObject->FileName.Buffer[1];
    hostname.Length = hostname.MaximumLength = IrpSp->FileObject->FileName.Length - sizeof(WCHAR);

    filename.Buffer = nullptr;
    filename.Length = filename.MaximumLength = 0;

    for (unsigned int i = 0; i < hostname.Length / sizeof(WCHAR); i++) {
        if (hostname.Buffer[i] == '\\') {
            filename.Length = filename.MaximumLength = hostname.Length - (i * sizeof(WCHAR)) - sizeof(WCHAR);
            filename.Buffer = &hostname.Buffer[i + 1];

            hostname.Length = hostname.MaximumLength = i * sizeof(WCHAR);

            break;
        }
    }

    Status = add_connexion(&hostname, &conn);
    if (!NT_SUCCESS(Status)) {
        ERR("add_connexion returned %08x\n", Status);
        return Status;
    }

    Status = conn->create_file(Irp, &filename);
    if (!NT_SUCCESS(Status))
        ERR("smb_connexion::create_file returned %08x\n", Status);

    InterlockedDecrement(&conn->refcount);

    return Status;
}

static NTSTATUS __stdcall drv_create(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    bool top_level;

    FsRtlEnterFileSystem();

    TRACE("create (flags = %x)\n", Irp->Flags);

    top_level = is_top_level(Irp);

    if (DeviceObject != master_devobj) {
        ERR("unknown object %p\n", DeviceObject);
        Status = STATUS_INVALID_PARAMETER;
    } else if (!IrpSp->FileObject) {
        ERR("FileObject was NULL\n");
        Status = STATUS_INVALID_PARAMETER;
    } else if (IrpSp->FileObject->FileName.Length == 0) {
        TRACE("create called for device object\n");

        Irp->IoStatus.Information = FILE_OPENED;
        Status = STATUS_SUCCESS;
    } else
        Status = create_file(Irp);

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    TRACE("create returning %08x\n", Status);

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS __stdcall drv_close(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    TRACE("(%p, %p)\n", DeviceObject, Irp);

    top_level = is_top_level(Irp);

    Irp->IoStatus.Information = 0;

    if (DeviceObject == master_devobj) {
        if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
            auto obj = CONTAINING_RECORD(IrpSp->FileObject->FsContext, smb_object, header);

            Status = obj->tree->close_file(obj, IrpSp->FileObject);
        } else {
            TRACE("closing file system\n");
            Status = STATUS_SUCCESS;
        }
    } else
        Status = STATUS_INVALID_PARAMETER;

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    TRACE("returning %08x\n", Status);

    FsRtlExitFileSystem();

    return Status;
}

static bool potential_connexion(PUNICODE_STRING hostname) {
    NTSTATUS Status;
    smb_connexion* conn;

    Status = add_connexion(hostname, &conn);

    if (NT_SUCCESS(Status))
        InterlockedDecrement(&conn->refcount);

    return NT_SUCCESS(Status);
}

static NTSTATUS redir_query_path(QUERY_PATH_REQUEST* qpreq, ULONG in_length, QUERY_PATH_RESPONSE* qpresp,
                                 ULONG out_length, KPROCESSOR_MODE processor_mode) {
    TRACE("(%p, %u, %p, %u, %u)\n", qpreq, in_length, qpresp, out_length, processor_mode);

    if (in_length < sizeof(ULONG))
        return STATUS_INVALID_PARAMETER;

    if (in_length < offsetof(QUERY_PATH_REQUEST, FilePathName) + qpreq->PathNameLength)
        return STATUS_INVALID_PARAMETER;

    if (out_length < sizeof(QUERY_PATH_RESPONSE))
        return STATUS_INVALID_PARAMETER;

    if (processor_mode != KernelMode)
        return STATUS_ACCESS_DENIED;

    if (qpreq->PathNameLength > sizeof(WCHAR) && qpreq->FilePathName[0] == '\\') {
        UNICODE_STRING hostname;
        unsigned int i;

        hostname.Buffer = &qpreq->FilePathName[1];

        for (i = 1; i < qpreq->PathNameLength / sizeof(WCHAR); i++) {
            if (qpreq->FilePathName[i] == '\\' || qpreq->FilePathName[i] == '/')
                break;
        }

        hostname.Length = hostname.MaximumLength = (i - 1) * sizeof(WCHAR);

        if (potential_connexion(&hostname)) {
            qpresp->LengthAccepted = i * sizeof(WCHAR);

            return STATUS_SUCCESS;
        }
    }

    return STATUS_INVALID_PARAMETER; // FIXME - don't think this is correct - there should be something meaning "not ours" or somesuch
}

static NTSTATUS unload() {
    // FIXME - should require unload driver privilege

    ExAcquireResourceSharedLite(&connexion_lock, true);

    {
        LIST_ENTRY* le = connexion_list.Flink;

        while (le != &connexion_list) {
            auto conn = CONTAINING_RECORD(le, smb_connexion, list_entry);

            conn->purge_cache();

            le = le->Flink;
        }
    }

    ExReleaseResourceLite(&connexion_lock);

    if (mup_handle) {
        FsRtlDeregisterUncProvider(mup_handle);
        mup_handle = nullptr;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS control_ioctl(PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_REDIR_QUERY_PATH:
            Status = redir_query_path((QUERY_PATH_REQUEST*)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer,
                                      IrpSp->Parameters.FileSystemControl.InputBufferLength, (QUERY_PATH_RESPONSE*)Irp->UserBuffer,
                                      IrpSp->Parameters.FileSystemControl.OutputBufferLength, Irp->RequestorMode);
            break;

        case IOCTL_SMBFS_UNLOAD:
            Status = unload();
            break;

        default:
            TRACE("unhandled ioctl %x\n", IrpSp->Parameters.DeviceIoControl.IoControlCode);
            Status = STATUS_NOT_IMPLEMENTED;
            break;
    }

    return Status;
}

static NTSTATUS __stdcall drv_device_control(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);

    Irp->IoStatus.Information = 0;

    if (DeviceObject != master_devobj) {
        ERR("unknown object %p\n", DeviceObject);
        Status = STATUS_INVALID_PARAMETER;
    } else
        Status = control_ioctl(Irp);

    Irp->IoStatus.Status = Status;

    if (Status != STATUS_PENDING)
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

    TRACE("returning %08x\n", Status);

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS __stdcall drv_directory_control(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS Status;
    bool top_level;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    FsRtlEnterFileSystem();

    TRACE("(%p, %p)\n", DeviceObject, Irp);

    top_level = is_top_level(Irp);

    Irp->IoStatus.Information = 0;

    if (DeviceObject != master_devobj) {
        ERR("unknown object %p\n", DeviceObject);
        Status = STATUS_INVALID_PARAMETER;
    } else if (!IrpSp->FileObject) {
        ERR("FileObject is NULL\n");
        Status = STATUS_INVALID_PARAMETER;
    } else if (!IrpSp->FileObject->FsContext) {
        ERR("FCB is NULL\n");
        Status = STATUS_INVALID_PARAMETER;
    } else {
        auto obj = CONTAINING_RECORD(IrpSp->FileObject->FsContext, smb_object, header);

        Status = obj->directory_control(Irp);
    }

    Irp->IoStatus.Status = Status;

    if (Status != STATUS_PENDING)
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

    TRACE("returning %08x\n", Status);

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS __stdcall drv_read(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    TRACE("(%p, %p)\n", DeviceObject, Irp);

    top_level = is_top_level(Irp);

    Irp->IoStatus.Information = 0;

    if (DeviceObject == master_devobj) {
        if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
            auto obj = CONTAINING_RECORD(IrpSp->FileObject->FsContext, smb_object, header);

            Status = obj->read(Irp);

            if (IrpSp->FileObject->Flags & FO_SYNCHRONOUS_IO && !(Irp->Flags & IRP_PAGING_IO))
                IrpSp->FileObject->CurrentByteOffset.QuadPart = IrpSp->Parameters.Read.ByteOffset.QuadPart + Irp->IoStatus.Information;
        } else
            Status = STATUS_INVALID_PARAMETER;
    } else
        Status = STATUS_INVALID_PARAMETER;

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    TRACE("returning %08x\n", Status);

    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS __stdcall drv_write(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    TRACE("(%p, %p)\n", DeviceObject, Irp);

    top_level = is_top_level(Irp);

    Irp->IoStatus.Information = 0;

    if (DeviceObject == master_devobj) {
        if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
            auto obj = CONTAINING_RECORD(IrpSp->FileObject->FsContext, smb_object, header);

            Status = obj->write(Irp);

            if (IrpSp->FileObject->Flags & FO_SYNCHRONOUS_IO && !(Irp->Flags & IRP_PAGING_IO))
                IrpSp->FileObject->CurrentByteOffset.QuadPart = IrpSp->Parameters.Read.ByteOffset.QuadPart + Irp->IoStatus.Information;
        } else
            Status = STATUS_INVALID_PARAMETER;
    } else
        Status = STATUS_INVALID_PARAMETER;

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    TRACE("returning %08x\n", Status);

    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS __stdcall drv_query_information(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    TRACE("(%p, %p)\n", DeviceObject, Irp);

    top_level = is_top_level(Irp);

    Irp->IoStatus.Information = 0;

    if (DeviceObject == master_devobj) {
        if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
            auto obj = CONTAINING_RECORD(IrpSp->FileObject->FsContext, smb_object, header);

            Status = obj->query_information(Irp);
        } else
            Status = STATUS_INVALID_PARAMETER;
    } else
        Status = STATUS_INVALID_PARAMETER;

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    TRACE("returning %08x\n", Status);

    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS __stdcall drv_set_information(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    TRACE("(%p, %p)\n", DeviceObject, Irp);

    top_level = is_top_level(Irp);

    Irp->IoStatus.Information = 0;

    if (DeviceObject == master_devobj) {
        if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
            auto obj = CONTAINING_RECORD(IrpSp->FileObject->FsContext, smb_object, header);

            Status = obj->set_information(Irp);
        } else
            Status = STATUS_INVALID_PARAMETER;
    } else
        Status = STATUS_INVALID_PARAMETER;

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    TRACE("returning %08x\n", Status);

    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS __stdcall drv_query_volume_information(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    TRACE("(%p, %p)\n", DeviceObject, Irp);

    top_level = is_top_level(Irp);

    Irp->IoStatus.Information = 0;

    if (DeviceObject == master_devobj) {
        if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
            auto obj = CONTAINING_RECORD(IrpSp->FileObject->FsContext, smb_object, header);

            Status = obj->query_volume_information(Irp);
        } else
            Status = STATUS_INVALID_PARAMETER;
    } else
        Status = STATUS_INVALID_PARAMETER;

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    TRACE("returning %08x\n", Status);

    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS __stdcall drv_filesystem_control(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    TRACE("(%p, %p)\n", DeviceObject, Irp);

    top_level = is_top_level(Irp);

    Irp->IoStatus.Information = 0;

    if (DeviceObject == master_devobj) {
        if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
            auto obj = CONTAINING_RECORD(IrpSp->FileObject->FsContext, smb_object, header);

            Status = obj->filesystem_control(Irp);
        } else
            Status = STATUS_INVALID_PARAMETER;
    } else
        Status = STATUS_INVALID_PARAMETER;

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    TRACE("returning %08x\n", Status);

    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS __stdcall drv_query_security(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    TRACE("(%p, %p)\n", DeviceObject, Irp);

    top_level = is_top_level(Irp);

    Irp->IoStatus.Information = 0;

    if (DeviceObject == master_devobj) {
        if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
            auto obj = CONTAINING_RECORD(IrpSp->FileObject->FsContext, smb_object, header);

            Status = obj->query_security(Irp);
        } else
            Status = STATUS_INVALID_PARAMETER;
    } else
        Status = STATUS_INVALID_PARAMETER;

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    TRACE("returning %08x\n", Status);

    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS __stdcall drv_set_security(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    TRACE("(%p, %p)\n", DeviceObject, Irp);

    top_level = is_top_level(Irp);

    Irp->IoStatus.Information = 0;

    if (DeviceObject == master_devobj) {
        if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
            auto obj = CONTAINING_RECORD(IrpSp->FileObject->FsContext, smb_object, header);

            Status = obj->set_security(Irp);
        } else
            Status = STATUS_INVALID_PARAMETER;
    } else
        Status = STATUS_INVALID_PARAMETER;

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    TRACE("returning %08x\n", Status);

    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS __stdcall drv_lock(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    TRACE("(%p, %p)\n", DeviceObject, Irp);

    top_level = is_top_level(Irp);

    Irp->IoStatus.Information = 0;

    if (DeviceObject == master_devobj) {
        if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
            auto obj = CONTAINING_RECORD(IrpSp->FileObject->FsContext, smb_object, header);

            Status = obj->lock(Irp);
        } else
            Status = STATUS_INVALID_PARAMETER;
    } else
        Status = STATUS_INVALID_PARAMETER;

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    TRACE("returning %08x\n", Status);

    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS __stdcall drv_flush(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    TRACE("(%p, %p)\n", DeviceObject, Irp);

    top_level = is_top_level(Irp);

    Irp->IoStatus.Information = 0;

    if (DeviceObject == master_devobj) {
        if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
            auto obj = CONTAINING_RECORD(IrpSp->FileObject->FsContext, smb_object, header);

            Status = obj->flush(Irp);
        } else
            Status = STATUS_INVALID_PARAMETER;
    } else
        Status = STATUS_INVALID_PARAMETER;

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    TRACE("returning %08x\n", Status);

    FsRtlExitFileSystem();

    return Status;
}

static void connexion_reap_thread() {
    KTIMER timer;
    LARGE_INTEGER due_time;

    TRACE("starting connexion reap thread\n");

    KeInitializeTimer(&timer);

    due_time.QuadPart = CONNEXION_REAP_THREAD_INTERVAL * -10000000;

    KeSetTimer(&timer, due_time, nullptr);

    while (true) {
        void* objs[2];
        LIST_ENTRY dead_head;
        LARGE_INTEGER time;

        time.QuadPart = 0;

        objs[0] = &timer;
        objs[1] = &driver_unload_event;

        KeWaitForMultipleObjects(2, objs, WaitAny, Executive, KernelMode, false, nullptr, nullptr);

        if (KeReadStateEvent(&driver_unload_event)) {
            KeCancelTimer(&timer);
            break;
        }

        InitializeListHead(&dead_head);

        // move inactive connexions to a local list...

        ExAcquireResourceExclusiveLite(&connexion_lock, true);

        LIST_ENTRY* le = connexion_list.Flink;
        while (le != &connexion_list) {
            auto le2 = le->Flink;
            auto conn = CONTAINING_RECORD(le, smb_connexion, list_entry);

            if (conn->refcount == 0) {
                ExAcquireResourceExclusiveLite(&conn->session_lock, true);

                if (time.QuadPart == 0)
                    KeQuerySystemTime(&time);

                if (conn->refcount == 0 && conn->last_activity + (CONNEXION_AGE * 10000000ull) <= (uint64_t)time.QuadPart) {
                    RemoveEntryList(&conn->list_entry);
                    InsertTailList(&dead_head, &conn->list_entry);
                }

                ExReleaseResourceLite(&conn->session_lock);
            }

            le = le2;
        }

        ExReleaseResourceLite(&connexion_lock);

        // ...and then free them

        while (!IsListEmpty(&dead_head)) {
            auto conn = CONTAINING_RECORD(RemoveHeadList(&dead_head), smb_connexion, list_entry);

            TRACE("freeing connexion %p\n", conn);

            conn->smb_connexion::~smb_connexion();
            ExFreePool(conn);
        }

        KeSetTimer(&timer, due_time, nullptr);
    }

    TRACE("end of connexion reap thread\n");

    ZwClose(connexion_reap_thread_handle);
    connexion_reap_thread_handle = nullptr;

    KeSetEvent(&connexion_reap_thread_quit_event, 0, false);
}

extern "C" NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
    NTSTATUS Status;
    UNICODE_STRING device_name_us;
    OBJECT_ATTRIBUTES oa;

    drvobj = DriverObject;

#ifdef _DEBUG
    logger = new serial_logger;

    if (!logger->okay()) {
        delete logger;
        logger = nullptr;
    }
#endif

    device_name_us.Buffer = (WCHAR*)device_name;
    device_name_us.Length = device_name_us.MaximumLength = sizeof(device_name) - sizeof(WCHAR);

    Status = IoCreateDevice(DriverObject, 0, &device_name_us, FILE_DEVICE_NETWORK_FILE_SYSTEM,
                            0, false, &master_devobj);
    if (!NT_SUCCESS(Status)) {
        ERR("IoCreateDevice returned %08x\n");

#ifdef _DEBUG
        if (logger)
            delete logger;
#endif

        return Status;
    }

    master_devobj->Flags |= DO_DIRECT_IO;

    ExInitializeResourceLite(&connexion_lock);
    InitializeListHead(&connexion_list);

    DriverObject->DriverUnload = DriverUnload;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = drv_create;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = drv_close;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = drv_device_control;
    DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = drv_filesystem_control;
    DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = drv_directory_control;
    DriverObject->MajorFunction[IRP_MJ_READ] = drv_read;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = drv_write;
    DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = drv_query_information;
    DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = drv_set_information;
    DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = drv_query_volume_information;
    DriverObject->MajorFunction[IRP_MJ_QUERY_SECURITY] = drv_query_security;
    DriverObject->MajorFunction[IRP_MJ_SET_SECURITY] = drv_set_security;
    DriverObject->MajorFunction[IRP_MJ_LOCK_CONTROL] = drv_lock;
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = drv_flush;

    master_devobj->Flags &= ~DO_DEVICE_INITIALIZING;

    Status = FsRtlRegisterUncProvider(&mup_handle, &device_name_us, false); // FIXME - support mailslots?
    if (!NT_SUCCESS(Status))
        ERR("FsRtlRegisterUncProvider returned %08x\n", Status);

    InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    KeInitializeEvent(&connexion_reap_thread_quit_event, NotificationEvent, false);
    KeInitializeEvent(&driver_unload_event, NotificationEvent, false);

    Status = PsCreateSystemThread(&connexion_reap_thread_handle, 0, &oa, nullptr, nullptr, [](void*) {
        connexion_reap_thread();
    }, nullptr);
    if (!NT_SUCCESS(Status))
        ERR("PsCreateSystemThread returned %08x\n", Status);

    return STATUS_SUCCESS;
}
