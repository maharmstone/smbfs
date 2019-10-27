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
#include <wnnc.h>
#include <stddef.h>

#define SMBFS_NODE_TYPE_FCB 0x229f

smb_object::smb_object(smb_tree* tree, PFILE_OBJECT FileObject) {
    InterlockedIncrement(&tree->refcount);

    this->tree = tree;
    this->FileObject = FileObject;

    header.NodeTypeCode = SMBFS_NODE_TYPE_FCB;
    header.NodeByteSize = sizeof(FSRTL_ADVANCED_FCB_HEADER);

    nonpaged = (smb_file_nonpaged*)ExAllocatePoolWithTag(NonPagedPool, sizeof(smb_file_nonpaged), ALLOC_TAG);
    if (!nonpaged) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        return;
    }

    ExInitializeResourceLite(&nonpaged->paging_resource);
    header.PagingIoResource = &nonpaged->paging_resource;

    ExInitializeFastMutex(&nonpaged->header_mutex);
    FsRtlSetupAdvancedHeader(&header, &nonpaged->header_mutex);

    ExInitializeResourceLite(&nonpaged->resource);
    header.Resource = &nonpaged->resource;

    RtlZeroMemory(&nonpaged->segment_object, sizeof(nonpaged->segment_object));

    InitializeListHead(&nonpaged->locks);
    KeInitializeSpinLock(&nonpaged->locks_spinlock);

    Status = STATUS_SUCCESS;
}

smb_object::~smb_object() {
    if (nonpaged) {
        KIRQL irql;

        ExDeleteResourceLite(&nonpaged->resource);
        ExDeleteResourceLite(&nonpaged->paging_resource);

        auto np = nonpaged;

        KeAcquireSpinLock(&np->locks_spinlock, &irql);

        while (!IsListEmpty(&np->locks)) {
            auto l = CONTAINING_RECORD(RemoveHeadList(&np->locks), smb_lock, list_entry);

            ExFreePool(l);
        }

        KeReleaseSpinLock(&np->locks_spinlock, irql);

        ExFreePool(nonpaged);
    }

    InterlockedDecrement(&tree->refcount);
}

NTSTATUS smb_object::directory_control(PIRP) {
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS smb_object::close(PFILE_OBJECT) {
    return STATUS_SUCCESS;
}

NTSTATUS smb_object::read(PIRP) {
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS smb_object::write(PIRP) {
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS smb_object::query_information(PIRP) {
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS smb_object::set_information(PIRP) {
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS smb_object::query_volume_information(PIRP) {
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS smb_object::query_security(PIRP) {
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS smb_object::set_security(PIRP) {
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS smb_object::lock(PIRP) {
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS smb_object::flush(PIRP) {
    return STATUS_INVALID_PARAMETER;
}

void smb_object::purge_cache() {
}

NTSTATUS smb_object::send_ioctl_request_msg(void* input, ULONG input_len, uint32_t control_code, bool fsctl,
                                            uint32_t output_len, msg_wait* mw) {
    size_t msg_len = sizeof(smb2_ioctl_request) + input_len;
    NTSTATUS Status;

    auto msg = (smb2_ioctl_request*)ExAllocatePoolWithTag(PagedPool, msg_len, ALLOC_TAG);

    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    tree->sess->conn->setup_smb2_header(msg, msg_len, tree->sess->session_id, tree->tree_id);

    msg->Command = SMB2_OP_IOCTL;

    msg->StructureSize = (sizeof(smb2_ioctl_request) - sizeof(smb2_header)) | 1;
    msg->Reserved = 0;
    msg->CtlCode = control_code;
    msg->FileId = FileId;
    msg->InputOffset = input_len > 0 ? (sizeof(smb2_ioctl_request) - sizeof(uint32_t)) : 0;
    msg->InputCount = input_len;
    msg->MaxInputResponse = 0; // FIXME?
    msg->OutputOffset = 0;
    msg->OutputCount = 0;
    msg->MaxOutputResponse = output_len;
    msg->Flags = fsctl ? SMB2_0_IOCTL_IS_FSCTL : 0;
    msg->Reserved2 = 0;

    if (input_len > 0)
        RtlCopyMemory((uint8_t*)msg + msg->InputOffset + sizeof(uint32_t), input, input_len);

    Status = tree->sess->conn->send(msg, msg_len, mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_connexion::send returned %08x\n", Status);
        ExFreePool(msg);
        return Status;
    }

    ExFreePool(msg);

    return Status;
}

NTSTATUS smb_object::filesystem_control(PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    void* in_buf;
    msg_wait mw;
    char* respbuf;
    size_t resp_len;
    void* out_buf;

    TRACE("(%p, %p)\n", this, Irp);

    TRACE("fsctl %x (device type = %x, function = %x, method = %x, access = %x)\n",
          IrpSp->Parameters.FileSystemControl.FsControlCode, IrpSp->Parameters.FileSystemControl.FsControlCode >> 16,
          (IrpSp->Parameters.FileSystemControl.FsControlCode >> 2) & 0xfff, IrpSp->Parameters.FileSystemControl.FsControlCode & 0x3,
          (IrpSp->Parameters.FileSystemControl.FsControlCode >> 14) & 0x3);

    tree->update_last_activity();

    uint8_t method = IrpSp->Parameters.FileSystemControl.FsControlCode & 0x3;

    if (method == METHOD_NEITHER)
        in_buf = IrpSp->Parameters.FileSystemControl.Type3InputBuffer;
    else
        in_buf = Irp->AssociatedIrp.SystemBuffer;

    Status = send_ioctl_request_msg(in_buf, IrpSp->Parameters.FileSystemControl.InputBufferLength,
                                    IrpSp->Parameters.FileSystemControl.FsControlCode, true,
                                    IrpSp->Parameters.FileSystemControl.OutputBufferLength, &mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_object::send_ioctl_request_msg returned %08x\n", Status);
        return Status;
    }

    Status = tree->sess->conn->wait_for_response(&mw, &respbuf, &resp_len, Irp);
    if (Status == STATUS_TIMEOUT) {
        ERR("timeout waiting for response\n");
        return Status;
    } else if (!NT_SUCCESS(Status)) {
        ERR("wait_for_response returned %08x\n", Status);
        return Status;
    }

    Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_USER_SESSION_DELETED)
            tree->sess->dead = true;

        ERR("server returned %08x in reply to ioctl message\n", Status);
        ExFreePool(respbuf);
        return Status;
    }

    if (resp_len < sizeof(smb2_ioctl_response) - sizeof(uint32_t)) {
        ERR("response was %u bytes, expected at least %u\n", resp_len, sizeof(smb2_ioctl_response) - sizeof(uint32_t));
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    auto resp = reinterpret_cast<smb2_ioctl_response*>(respbuf);

    if (resp->InputOffset >= (uint16_t)resp_len || resp->InputOffset + resp->InputCount >= (uint16_t)resp_len ||
        resp->OutputOffset >= (uint16_t)resp_len || resp->OutputOffset + resp->OutputCount >= (uint16_t)resp_len) {
        ERR("invalid offsets in response\n");
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    if (resp->OutputCount > IrpSp->Parameters.FileSystemControl.OutputBufferLength) {
        ERR("buffer returned was %u bytes, despite maximum being %u\n", resp->OutputCount, IrpSp->Parameters.FileSystemControl.OutputBufferLength);
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    if (method == METHOD_OUT_DIRECT)
        out_buf = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    else
        out_buf = Irp->UserBuffer;

    RtlCopyMemory(out_buf, (uint8_t*)resp + sizeof(uint32_t) + resp->OutputOffset, resp->OutputCount);

    Irp->IoStatus.Information = resp->OutputCount;

    ExFreePool(respbuf);

    return STATUS_SUCCESS;
}

smb_file::smb_file(smb_tree* tree, PFILE_OBJECT FileObject, PUNICODE_STRING filename, smb2_create_response* resp) : smb_object(tree, FileObject) {
    type = smb_object_type::file;

    header.AllocationSize.QuadPart = resp->AllocationSize;
    header.FileSize.QuadPart = header.ValidDataLength.QuadPart = resp->EndOfFile;

    CreationTime = resp->CreationTime;
    LastAccessTime = resp->LastAccessTime;
    LastWriteTime = resp->LastWriteTime;
    ChangeTime = resp->ChangeTime;
    AllocationSize = resp->AllocationSize;
    EndOfFile = resp->EndOfFile;
    FileAttributes = resp->FileAttributes;
    FileId = resp->FileId;

    query_string.Buffer = nullptr;
    query_string.Length = query_string.MaximumLength = 0;

    if (filename && filename->Length > 0) {
        name.Buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, filename->Length, ALLOC_TAG);
        if (!name.Buffer) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            return;
        }

        RtlCopyMemory(name.Buffer, filename->Buffer, filename->Length);
        name.Length = name.MaximumLength = filename->Length;
    } else {
        name.Buffer = nullptr;
        name.Length = name.MaximumLength = 0;
    }
}

smb_file::~smb_file() {
    if (query_string.Buffer)
        ExFreePool(query_string.Buffer);

    if (name.Buffer)
        ExFreePool(name.Buffer);
}

NTSTATUS smb_file::send_query_directory_msg(PUNICODE_STRING query_string, uint8_t file_information_class,
                                            uint32_t file_index, uint8_t flags, uint32_t length, msg_wait* mw) {
    size_t msg_len = sizeof(smb2_query_directory_request) + (query_string ? query_string->Length : 1);
    NTSTATUS Status;

    auto msg = (smb2_query_directory_request*)ExAllocatePoolWithTag(PagedPool, msg_len, ALLOC_TAG);

    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    tree->sess->conn->setup_smb2_header(msg, msg_len, tree->sess->session_id, tree->tree_id);

    msg->Command = SMB2_OP_QUERY_DIRECTORY;

    msg->StructureSize = (sizeof(smb2_query_directory_request) - sizeof(smb2_header)) | 1;
    msg->FileInformationClass = file_information_class;
    msg->Flags = flags;
    msg->FileIndex = file_index;
    msg->FileId = FileId;
    msg->FileNameOffset = query_string && query_string->Length > 0 ? (sizeof(smb2_query_directory_request) - sizeof(uint32_t)) : 0;
    msg->FileNameLength = query_string ? (uint16_t)query_string->Length : 0;
    msg->OutputBufferLength = length;

    if (query_string && query_string->Length > 0)
        RtlCopyMemory((uint8_t*)msg + msg->FileNameOffset + sizeof(uint32_t), query_string->Buffer, query_string->Length);

    Status = tree->sess->conn->send(msg, msg_len, mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_connexion::send returned %08x\n", Status);
        ExFreePool(msg);
        return Status;
    }

    ExFreePool(msg);

    return Status;
}

NTSTATUS smb_file::query_directory(PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    char* respbuf;
    size_t resp_len;
    msg_wait mw;

    tree->update_last_activity();

    if (!Irp->MdlAddress) {
        ERR("MDL was NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (IrpSp->Flags & SL_RESTART_SCAN || IrpSp->Parameters.QueryDirectory.FileName) {
        if (query_string.Buffer) {
            ExFreePool(query_string.Buffer);
            query_string.Buffer = nullptr;
            query_string.Length = query_string.MaximumLength = 0;
        }

        if (IrpSp->Parameters.QueryDirectory.FileName) {
            query_string.Buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, IrpSp->Parameters.QueryDirectory.FileName->Length, ALLOC_TAG);
            if (!query_string.Buffer) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlCopyMemory(query_string.Buffer, IrpSp->Parameters.QueryDirectory.FileName->Buffer, IrpSp->Parameters.QueryDirectory.FileName->Length);
            query_string.Length = query_string.MaximumLength = IrpSp->Parameters.QueryDirectory.FileName->Length;
        } else {
            query_string.Buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, sizeof(WCHAR), ALLOC_TAG);
            if (!query_string.Buffer) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            query_string.Buffer[0] = '*';
            query_string.Length = query_string.MaximumLength = sizeof(WCHAR);
        }
    }

    Status = send_query_directory_msg(query_string.Buffer ? &query_string : nullptr,
                                      IrpSp->Parameters.QueryDirectory.FileInformationClass,
                                      IrpSp->Parameters.QueryDirectory.FileIndex, IrpSp->Flags,
                                      IrpSp->Parameters.QueryDirectory.Length, &mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_file::send_query_directory_msg returned %08x\n", Status);
        return Status;
    }

    Status = tree->sess->conn->wait_for_response(&mw, &respbuf, &resp_len, Irp);
    if (Status == STATUS_TIMEOUT) {
        ERR("timeout waiting for response\n");
        return Status;
    } else if (!NT_SUCCESS(Status)) {
        ERR("wait_for_response returned %08x\n", Status);
        return Status;
    }

    Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_USER_SESSION_DELETED)
            tree->sess->dead = true;

        if (Status == STATUS_NO_MORE_FILES) {
            TRACE("server returned %08x in reply to query directory message\n", Status);
        } else {
            ERR("server returned %08x in reply to query directory message\n", Status);
        }

        ExFreePool(respbuf);
        return Status;
    }

    if (resp_len < sizeof(smb2_query_directory_response) - sizeof(uint32_t)) {
        ERR("response was %u bytes, expected at least %u\n", resp_len, sizeof(smb2_query_directory_response) - sizeof(uint32_t));
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    auto resp = reinterpret_cast<smb2_query_directory_response*>(respbuf);

    if (resp->OutputBufferOffset >= (uint16_t)resp_len || resp->OutputBufferOffset + resp->OutputBufferLength >= (uint16_t)resp_len) {
        ERR("invalid offsets in response\n");
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    if (resp->OutputBufferLength > IrpSp->Parameters.QueryDirectory.Length) {
        ERR("buffer returned was %u bytes, despite maximum being %u\n", resp->OutputBufferLength, IrpSp->Parameters.QueryDirectory.Length);
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    auto buf = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

    RtlCopyMemory(buf, (uint8_t*)resp + sizeof(uint32_t) + resp->OutputBufferOffset, resp->OutputBufferLength);

    Irp->IoStatus.Information = resp->OutputBufferLength;

    ExFreePool(respbuf);

    return STATUS_SUCCESS;
}

NTSTATUS smb_file::send_change_notify_msg(bool watch_tree, uint32_t length, uint32_t completion_filter, msg_wait* mw) {
    size_t msg_len = sizeof(smb2_change_notify_request);
    NTSTATUS Status;

    auto msg = (smb2_change_notify_request*)ExAllocatePoolWithTag(PagedPool, msg_len, ALLOC_TAG);

    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    tree->sess->conn->setup_smb2_header(msg, msg_len, tree->sess->session_id, tree->tree_id);

    msg->Command = SMB2_OP_NOTIFY;

    msg->StructureSize = sizeof(smb2_change_notify_request) - sizeof(smb2_header);
    msg->Flags = watch_tree ? SMB2_WATCH_TREE : 0;
    msg->OutputBufferLength = length;
    msg->FileId = FileId;
    msg->CompletionFilter = completion_filter;
    msg->Reserved = 0;

    Status = tree->sess->conn->send(msg, msg_len, mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_connexion::send returned %08x\n", Status);
        ExFreePool(msg);
        return Status;
    }

    ExFreePool(msg);

    return Status;
}

static void notify_change_pending(smb_connexion* conn, msg_wait* mw, PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    char* respbuf;
    size_t resp_len;

    Status = conn->wait_for_response(mw, &respbuf, &resp_len, Irp, false, true);

    if (!NT_SUCCESS(Status)) {
        ERR("wait_for_response returned %08x\n", Status);
        ExFreePool(mw);

        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return;
    }

    ExFreePool(mw);

    Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

    if (!NT_SUCCESS(Status)) {
        ERR("server returned %08x in reply to notify directory message\n", Status);
        ExFreePool(respbuf);

        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return;
    }

    if (resp_len < sizeof(smb2_change_notify_response) - sizeof(uint32_t)) {
        ERR("response was %u bytes, expected at least %u\n", resp_len, sizeof(smb2_change_notify_response) - sizeof(uint32_t));
        ExFreePool(respbuf);

        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return;
    }

    auto resp = reinterpret_cast<smb2_change_notify_response*>(respbuf);

    if (resp->OutputBufferOffset >= (uint16_t)resp_len || resp->OutputBufferOffset + resp->OutputBufferLength >= (uint16_t)resp_len) {
        ERR("invalid offsets in response\n");
        ExFreePool(respbuf);

        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return;
    }

    if (resp->OutputBufferLength > IrpSp->Parameters.NotifyDirectory.Length) {
        ERR("buffer returned was %u bytes, despite maximum being %u\n", resp->OutputBufferLength, IrpSp->Parameters.NotifyDirectory.Length);
        ExFreePool(respbuf);

        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return;
    }

    if (!(Irp->MdlAddress->MdlFlags & (MDL_PAGES_LOCKED | MDL_PARTIAL))) {
        _SEH2_TRY {
            MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoWriteAccess);
        } _SEH2_EXCEPT (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        } _SEH2_END;

        if (!NT_SUCCESS(Status)) {
            ERR("MmProbeAndLockPages threw exception %08x\n", Status);
            ExFreePool(respbuf);

            Irp->IoStatus.Status = Status;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return;
        }
    }

    auto buf = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

    RtlCopyMemory(buf, (uint8_t*)resp + sizeof(uint32_t) + resp->OutputBufferOffset, resp->OutputBufferLength);

    Irp->IoStatus.Information = resp->OutputBufferLength;

    ExFreePool(respbuf);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

typedef struct {
    smb_connexion* conn;
    msg_wait* mw;
    PIRP Irp;
    HANDLE thread_handle;
} notify_change_ctx;

NTSTATUS smb_file::notify_change_directory(PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    msg_wait* mw;
    char* respbuf;
    size_t resp_len;

    tree->update_last_activity();

    if (!Irp->MdlAddress) {
        ERR("MDL was NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    mw = (msg_wait*)ExAllocatePoolWithTag(NonPagedPool, sizeof(msg_wait), ALLOC_TAG);
    if (!mw) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = send_change_notify_msg(IrpSp->Flags & SL_WATCH_TREE, IrpSp->Parameters.NotifyDirectory.Length,
                                    IrpSp->Parameters.NotifyDirectory.CompletionFilter, mw);

    if (!NT_SUCCESS(Status)) {
        ERR("smb_file::send_query_directory_msg returned %08x\n", Status);
        ExFreePool(mw);
        return Status;
    }

    Status = tree->sess->conn->wait_for_response(mw, &respbuf, &resp_len, Irp, true);
    if (Status == STATUS_TIMEOUT) {
        ERR("timeout waiting for response\n");
        ExFreePool(mw);
        return Status;
    } else if (!NT_SUCCESS(Status)) {
        ERR("wait_for_response returned %08x\n", Status);
        ExFreePool(mw);
        return Status;
    }

    Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

    if (Status == STATUS_PENDING) {
        OBJECT_ATTRIBUTES oa;

        auto ncc = (notify_change_ctx*)ExAllocatePoolWithTag(NonPagedPool, sizeof(notify_change_ctx), ALLOC_TAG);
        if (!ncc) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ExFreePool(respbuf);

        InterlockedIncrement(&tree->sess->conn->refcount);

        ncc->conn = tree->sess->conn;
        ncc->mw = mw;
        ncc->Irp = Irp;

        InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

        Status = PsCreateSystemThread(&ncc->thread_handle, 0, &oa, nullptr, nullptr, [](void* ctx) {
            auto ncc = (notify_change_ctx*)ctx;

            notify_change_pending(ncc->conn, ncc->mw, ncc->Irp);

            InterlockedDecrement(&ncc->conn->refcount);

            ZwClose(ncc->thread_handle);
            ExFreePool(ncc);
        }, ncc);

        if (!NT_SUCCESS(Status)) {
            ERR("PsCreateSystemThread returned %08x\n", Status);

            InterlockedDecrement(&tree->sess->conn->refcount);
            ExFreePool(mw);
            ExFreePool(ncc);
            return Status;
        }

        IoMarkIrpPending(Irp);
        return STATUS_PENDING;
    }

    ExFreePool(mw);

    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_USER_SESSION_DELETED)
            tree->sess->dead = true;

        ERR("server returned %08x in reply to notify directory message\n", Status);
        ExFreePool(respbuf);
        return Status;
    }

    if (resp_len < sizeof(smb2_change_notify_response) - sizeof(uint32_t)) {
        ERR("response was %u bytes, expected at least %u\n", resp_len, sizeof(smb2_change_notify_response) - sizeof(uint32_t));
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    auto resp = reinterpret_cast<smb2_change_notify_response*>(respbuf);

    if (resp->OutputBufferOffset >= (uint16_t)resp_len || resp->OutputBufferOffset + resp->OutputBufferLength >= (uint16_t)resp_len) {
        ERR("invalid offsets in response\n");
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    if (resp->OutputBufferLength > IrpSp->Parameters.NotifyDirectory.Length) {
        ERR("buffer returned was %u bytes, despite maximum being %u\n", resp->OutputBufferLength, IrpSp->Parameters.NotifyDirectory.Length);
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    auto buf = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

    RtlCopyMemory(buf, (uint8_t*)resp + sizeof(uint32_t) + resp->OutputBufferOffset, resp->OutputBufferLength);

    Irp->IoStatus.Information = resp->OutputBufferLength;

    ExFreePool(respbuf);

    return STATUS_SUCCESS;
}

NTSTATUS smb_file::directory_control(PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    TRACE("(%p, %p)\n", this, Irp);

    switch (IrpSp->MinorFunction) {
        case IRP_MN_QUERY_DIRECTORY:
            return query_directory(Irp);

        case IRP_MN_NOTIFY_CHANGE_DIRECTORY:
            return notify_change_directory(Irp);

        default:
            return STATUS_NOT_SUPPORTED;
    }
}

NTSTATUS smb_file::close(PFILE_OBJECT FileObject) {
    size_t msg_len = sizeof(smb2_close_request);
    NTSTATUS Status;
    char* respbuf;
    size_t resp_len;
    msg_wait mw;

    CcUninitializeCacheMap(FileObject, nullptr, nullptr);

    auto msg = (smb2_close_request*)ExAllocatePoolWithTag(PagedPool, msg_len, ALLOC_TAG);

    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    tree->sess->conn->setup_smb2_header(msg, msg_len, tree->sess->session_id, tree->tree_id);

    msg->Command = SMB2_OP_CLOSE;

    msg->StructureSize = sizeof(smb2_close_request) - sizeof(smb2_header);
    msg->Flags = 0;
    msg->Reserved = 0;
    msg->FileId = FileId;

    Status = tree->sess->conn->send(msg, msg_len, &mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_connexion::send returned %08x\n", Status);
        ExFreePool(msg);
        return Status;
    }

    ExFreePool(msg);

    Status = tree->sess->conn->wait_for_response(&mw, &respbuf, &resp_len, nullptr);
    if (Status == STATUS_TIMEOUT) {
        ERR("timeout waiting for response\n");
        return Status;
    } else if (!NT_SUCCESS(Status)) {
        ERR("wait_for_response returned %08x\n", Status);
        return Status;
    }

    Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_USER_SESSION_DELETED)
            tree->sess->dead = true;

        ERR("server returned %08x in reply to close message\n", Status);
        ExFreePool(respbuf);
        return Status;
    }

    ExFreePool(respbuf);

    return Status;
}

NTSTATUS smb_file::send_read_msg(uint32_t length, uint64_t offset, msg_wait* mw) {
    size_t msg_len = sizeof(smb2_read_request) + 1;
    NTSTATUS Status;

    TRACE("(%p, %x, %I64x, %p)\n", this, length, offset, mw);

    auto msg = (smb2_read_request*)ExAllocatePoolWithTag(PagedPool, msg_len, ALLOC_TAG);

    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    tree->sess->conn->setup_smb2_header(msg, msg_len, tree->sess->session_id, tree->tree_id);

    msg->Command = SMB2_OP_READ;

    msg->StructureSize = (sizeof(smb2_read_request) - sizeof(smb2_header)) | 1;
    msg->Padding = 0;
    msg->Flags = 0;
    msg->Length = length;
    msg->Offset = offset;
    msg->FileId = FileId;
    msg->MinimumCount = 0;
    msg->Channel = 0;
    msg->RemainingBytes =0;
    msg->ReadChannelInfoOffset = 0;
    msg->ReadChannelInfoLength = 0;

    Status = tree->sess->conn->send(msg, msg_len, mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_connexion::send returned %08x\n", Status);
        ExFreePool(msg);
        return Status;
    }

    ExFreePool(msg);

    return Status;
}

NTSTATUS smb_file::read(PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    char* respbuf;
    size_t resp_len;
    msg_wait mw;
    uint64_t offset;
    uint32_t length, retlen = 0;

    TRACE("(%p, %p)\n", this, Irp);

    if (IrpSp->Parameters.Read.Length == 0)
        return STATUS_SUCCESS;

    tree->update_last_activity();

    if (!Irp->MdlAddress) {
        ERR("MDL was NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    auto buf = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

    offset = IrpSp->Parameters.Read.ByteOffset.QuadPart;
    length = IrpSp->Parameters.Read.Length;

    do {
        uint32_t to_read = length > tree->sess->conn->max_read ? tree->sess->conn->max_read : length;

        Status = send_read_msg(to_read, offset, &mw);
        if (!NT_SUCCESS(Status)) {
            ERR("smb_file::send_read_msg returned %08x\n", Status);
            return Status;
        }

        Status = tree->sess->conn->wait_for_response(&mw, &respbuf, &resp_len, Irp);
        if (Status == STATUS_TIMEOUT) {
            ERR("timeout waiting for response\n");
            return Status;
        } else if (!NT_SUCCESS(Status)) {
            ERR("wait_for_response returned %08x\n", Status);
            return Status;
        }

        Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

        if (Status == STATUS_END_OF_FILE) {
            Irp->IoStatus.Information = retlen;
            ExFreePool(respbuf);

            return retlen == 0 ? STATUS_END_OF_FILE : STATUS_SUCCESS;
        } else if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_USER_SESSION_DELETED)
                tree->sess->dead = true;

            ERR("server returned %08x in reply to read message\n", Status);
            ExFreePool(respbuf);
            return Status;
        }

        if (resp_len < sizeof(smb2_read_response) - sizeof(uint32_t)) {
            ERR("response was %u bytes, expected at least %u\n", resp_len, sizeof(smb2_read_response) - sizeof(uint32_t));
            ExFreePool(respbuf);
            return STATUS_INVALID_PARAMETER;
        }

        auto resp = reinterpret_cast<smb2_read_response*>(respbuf);

        if (resp->DataOffset >= resp_len || resp->DataOffset + resp->DataLength >= resp_len) {
            ERR("invalid offsets in response\n");
            ExFreePool(respbuf);
            return STATUS_INVALID_PARAMETER;
        }

        uint32_t data_length = resp->DataLength;

        if (IrpSp->Parameters.Read.Length - retlen < data_length)
            data_length = IrpSp->Parameters.Read.Length - retlen;

        RtlCopyMemory((uint8_t*)buf + retlen, (uint8_t*)resp + sizeof(uint32_t) + resp->DataOffset, data_length);

        ExFreePool(respbuf);

        if (retlen + data_length >= IrpSp->Parameters.Read.Length) {
            retlen = IrpSp->Parameters.Read.Length;
            break;
        }

        length -= data_length;
        offset += data_length;
        retlen += data_length;

        if (data_length < to_read) // short read, assume end of file
            break;
    } while (true);

    Irp->IoStatus.Information = retlen;

    return STATUS_SUCCESS;
}

NTSTATUS smb_file::send_write_msg(void* buf, uint32_t length, uint64_t offset, msg_wait* mw) {
    size_t msg_len = sizeof(smb2_write_request) + (length == 0 ? 1 : length);
    NTSTATUS Status;

    TRACE("(%p, %p, %x, %I64x, %p)\n", this, buf, length, offset, mw);

    auto msg = (smb2_write_request*)ExAllocatePoolWithTag(PagedPool, msg_len, ALLOC_TAG);

    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    tree->sess->conn->setup_smb2_header(msg, msg_len, tree->sess->session_id, tree->tree_id);

    msg->Command = SMB2_OP_WRITE;

    msg->StructureSize = (sizeof(smb2_write_request) - sizeof(smb2_header)) | 1;
    msg->DataOffset = sizeof(smb2_write_request) - sizeof(uint32_t);
    msg->Length = length;
    msg->Offset = offset;
    msg->FileId = FileId;
    msg->Channel = 0;
    msg->RemainingBytes = 0;
    msg->WriteChannelInfoOffset = 0;
    msg->WriteChannelInfoLength = 0;
    msg->Flags = 0;

    if (length > 0)
        RtlCopyMemory((uint8_t*)msg + msg->DataOffset + sizeof(uint32_t), buf, length);

    Status = tree->sess->conn->send(msg, msg_len, mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_connexion::send returned %08x\n", Status);
        ExFreePool(msg);
        return Status;
    }

    ExFreePool(msg);

    return Status;
}

NTSTATUS smb_file::write(PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    char* respbuf;
    size_t resp_len;
    msg_wait mw;
    uint64_t offset;
    uint32_t length, count, written = 0;

    TRACE("(%p, %p)\n", this, Irp);

    if (IrpSp->Parameters.Write.Length == 0)
        return STATUS_SUCCESS;

    tree->update_last_activity();

    if (!Irp->MdlAddress) {
        ERR("MDL was NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    auto buf = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

    offset = IrpSp->Parameters.Write.ByteOffset.QuadPart;
    length = IrpSp->Parameters.Write.Length;

    do {
        uint32_t to_write = length > tree->sess->conn->max_write ? tree->sess->conn->max_write : length;

        Status = send_write_msg((uint8_t*)buf + written, to_write, offset, &mw);
        if (!NT_SUCCESS(Status)) {
            ERR("smb_file::send_write_msg returned %08x\n", Status);
            return Status;
        }

        Status = tree->sess->conn->wait_for_response(&mw, &respbuf, &resp_len, Irp);
        if (Status == STATUS_TIMEOUT) {
            ERR("timeout waiting for response\n");
            return Status;
        } else if (!NT_SUCCESS(Status)) {
            ERR("wait_for_response returned %08x\n", Status);
            return Status;
        }

        Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_USER_SESSION_DELETED)
                tree->sess->dead = true;

            ERR("server returned %08x in reply to read message\n", Status);
            ExFreePool(respbuf);
            return Status;
        }

        if (resp_len < sizeof(smb2_write_response) - sizeof(uint32_t)) {
            ERR("response was %u bytes, expected at least %u\n", resp_len, sizeof(smb2_write_response) - sizeof(uint32_t));
            ExFreePool(respbuf);
            return STATUS_INVALID_PARAMETER;
        }

        auto resp = reinterpret_cast<smb2_write_response*>(respbuf);

        count = resp->Count;

        ExFreePool(respbuf);

        if (count > to_write)
            count = to_write;

        written += count;

        if (count >= length)
            break;

        offset += count;
        length -= count;
    } while (true);

    Irp->IoStatus.Information = written;

    return STATUS_SUCCESS;
}

NTSTATUS smb_file::send_query_info_msg(uint8_t info_type, uint8_t file_info_class, uint32_t length,
                                       uint32_t additional_info, msg_wait* mw) {
    size_t msg_len = sizeof(smb2_query_info_request);
    NTSTATUS Status;

    TRACE("(%p, %x, %x, %x, %p)\n", this, info_type, file_info_class, length, mw);

    auto msg = (smb2_query_info_request*)ExAllocatePoolWithTag(PagedPool, msg_len, ALLOC_TAG);

    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    tree->sess->conn->setup_smb2_header(msg, msg_len, tree->sess->session_id, tree->tree_id);

    msg->Command = SMB2_OP_GETINFO;

    msg->StructureSize = (sizeof(smb2_query_info_request) - sizeof(smb2_header)) | 1;
    msg->InfoType = info_type;
    msg->FileInfoClass = file_info_class;
    msg->OutputBufferLength = length;
    msg->InputBufferOffset = 0;
    msg->Reserved = 0;
    msg->InputBufferLength = 0;
    msg->AdditionalInformation = additional_info;
    msg->Flags = 0;
    msg->FileId = FileId;

    Status = tree->sess->conn->send(msg, msg_len, mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_connexion::send returned %08x\n", Status);
        ExFreePool(msg);
        return Status;
    }

    ExFreePool(msg);

    return Status;
}

NTSTATUS smb_file::query_file_name_information(PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    auto fni = (FILE_NAME_INFORMATION*)Irp->AssociatedIrp.SystemBuffer;

    TRACE("(%p, %p)\n", this, Irp);

    if (IrpSp->Parameters.QueryFile.Length < sizeof(ULONG))
        return STATUS_INVALID_PARAMETER;

    ExAcquireResourceSharedLite(&tree->name_lock, true);

    size_t name_len = sizeof(WCHAR) + tree->sess->conn->hostname.Length + sizeof(WCHAR) + tree->name.Length +
                      sizeof(WCHAR) + name.Length;


    fni->FileNameLength = name_len;

    size_t left = IrpSp->Parameters.QueryFile.Length - sizeof(ULONG);

    if (left < name_len)
        Irp->IoStatus.Information = IrpSp->Parameters.QueryFile.Length;
    else
        Irp->IoStatus.Information = name_len + sizeof(ULONG);

    WCHAR* p = &fni->FileName[0];

    if (left >= sizeof(WCHAR)) {
        *p = '\\';
        p++;
        left -= sizeof(WCHAR);
    } else {
        ExReleaseResourceLite(&tree->name_lock);
        return STATUS_BUFFER_OVERFLOW;
    }

    if (left >= tree->sess->conn->hostname.Length) {
        RtlCopyMemory(p, tree->sess->conn->hostname.Buffer, tree->sess->conn->hostname.Length);
        p += tree->sess->conn->hostname.Length / sizeof(WCHAR);
        left -= tree->sess->conn->hostname.Length;
    } else {
        RtlCopyMemory(p, tree->sess->conn->hostname.Buffer, left);
        ExReleaseResourceLite(&tree->name_lock);
        return STATUS_BUFFER_OVERFLOW;
    }

    if (left >= sizeof(WCHAR)) {
        *p = '\\';
        p++;
        left -= sizeof(WCHAR);
    } else {
        ExReleaseResourceLite(&tree->name_lock);
        return STATUS_BUFFER_OVERFLOW;
    }

    if (left >= tree->name.Length) {
        RtlCopyMemory(p, tree->name.Buffer, tree->name.Length);
        p += tree->name.Length / sizeof(WCHAR);
        left -= tree->name.Length;
    } else {
        RtlCopyMemory(p, tree->name.Buffer, left);
        ExReleaseResourceLite(&tree->name_lock);
        return STATUS_BUFFER_OVERFLOW;
    }

    if (left >= sizeof(WCHAR)) {
        *p = '\\';
        p++;
        left -= sizeof(WCHAR);
    } else {
        ExReleaseResourceLite(&tree->name_lock);
        return STATUS_BUFFER_OVERFLOW;
    }

    if (left >= name.Length)
        RtlCopyMemory(p, name.Buffer, name.Length);
    else {
        RtlCopyMemory(p, tree->name.Buffer, left);
        ExReleaseResourceLite(&tree->name_lock);
        return STATUS_BUFFER_OVERFLOW;
    }

    ExReleaseResourceLite(&tree->name_lock);

    return STATUS_SUCCESS;
}

NTSTATUS smb_file::query_file_remote_protocol_information(PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    void* buf = Irp->AssociatedIrp.SystemBuffer;
    ULONG buflen = IrpSp->Parameters.QueryFile.Length;
    FILE_REMOTE_PROTOCOL_INFORMATION frpi;

    RtlZeroMemory(&frpi, sizeof(FILE_REMOTE_PROTOCOL_INFORMATION));

    frpi.StructureVersion = 1;
    frpi.StructureSize = sizeof(FILE_REMOTE_PROTOCOL_INFORMATION);
    frpi.Protocol = WNNC_NET_SMB;
    frpi.ProtocolMajorVersion = tree->sess->conn->dialect >> 8;
    frpi.ProtocolMinorVersion = tree->sess->conn->dialect & 0xff;

    Irp->IoStatus.Information = buflen < sizeof(FILE_REMOTE_PROTOCOL_INFORMATION) ? buflen : sizeof(FILE_REMOTE_PROTOCOL_INFORMATION);

    RtlCopyMemory(buf, &frpi, Irp->IoStatus.Information);

    return buflen < sizeof(FILE_REMOTE_PROTOCOL_INFORMATION) ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

NTSTATUS smb_file::query_information(PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    char* respbuf;
    size_t resp_len;
    msg_wait mw;

    TRACE("(%p, %p)\n", this, Irp);

    tree->update_last_activity();

    if (IrpSp->Parameters.QueryFile.FileInformationClass == FileNameInformation)
        return query_file_name_information(Irp);
    else if (IrpSp->Parameters.QueryFile.FileInformationClass == FileRemoteProtocolInformation)
        return query_file_remote_protocol_information(Irp);

    Status = send_query_info_msg(SMB2_0_INFO_FILE, IrpSp->Parameters.QueryFile.FileInformationClass,
                                 IrpSp->Parameters.QueryFile.Length, 0, &mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_file::send_query_info_msg returned %08x\n", Status);
        return Status;
    }

    Status = tree->sess->conn->wait_for_response(&mw, &respbuf, &resp_len, Irp);
    if (Status == STATUS_TIMEOUT) {
        ERR("timeout waiting for response\n");
        return Status;
    } else if (!NT_SUCCESS(Status)) {
        ERR("wait_for_response returned %08x\n", Status);
        return Status;
    }

    Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW) {
        if (Status == STATUS_USER_SESSION_DELETED)
            tree->sess->dead = true;

        ERR("server returned %08x in reply to query information message\n", Status);
        ExFreePool(respbuf);
        return Status;
    }

    if (resp_len < sizeof(smb2_query_info_response) - sizeof(uint32_t)) {
        ERR("response was %u bytes, expected at least %u\n", resp_len, sizeof(smb2_query_info_response) - sizeof(uint32_t));
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    auto resp = reinterpret_cast<smb2_query_info_response*>(respbuf);

    if (resp->OutputBufferOffset >= (uint16_t)resp_len || resp->OutputBufferOffset + resp->OutputBufferLength >= (uint16_t)resp_len) {
        ERR("invalid offsets in response\n");
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    if (resp->OutputBufferLength > IrpSp->Parameters.QueryFile.Length) {
        ERR("buffer returned was %u bytes, despite maximum being %u\n", resp->OutputBufferLength, IrpSp->Parameters.QueryFile.Length);
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, (uint8_t*)resp + sizeof(uint32_t) + resp->OutputBufferOffset, resp->OutputBufferLength);

    Irp->IoStatus.Information = resp->OutputBufferLength;

    ExFreePool(respbuf);

    return Status;
}

NTSTATUS smb_file::send_set_info_msg(uint8_t info_type, uint8_t file_info_class, void* buf,
                                     uint32_t length, uint32_t additional_info, msg_wait* mw) {
    size_t msg_len = sizeof(smb2_set_info_request) + (length == 0 ? 1 : length);
    NTSTATUS Status;

    TRACE("(%p, %x, %x, %p, %x, %p)\n", this, info_type, file_info_class, buf, length, mw);

    auto msg = (smb2_set_info_request*)ExAllocatePoolWithTag(PagedPool, msg_len, ALLOC_TAG);

    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    tree->sess->conn->setup_smb2_header(msg, msg_len, tree->sess->session_id, tree->tree_id);

    msg->Command = SMB2_OP_SETINFO;

    msg->StructureSize = (sizeof(smb2_set_info_request) - sizeof(smb2_header)) | 1;
    msg->InfoType = info_type;
    msg->FileInfoClass = file_info_class;
    msg->BufferLength = length;
    msg->BufferOffset = length > 0 ? (sizeof(smb2_set_info_request) - sizeof(uint32_t)) : 0;
    msg->Reserved = 0;
    msg->AdditionalInformation = additional_info;
    msg->FileId = FileId;

    if (length > 0)
        RtlCopyMemory((uint8_t*)msg + msg->BufferOffset + sizeof(uint32_t), buf, length);

    Status = tree->sess->conn->send(msg, msg_len, mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_connexion::send returned %08x\n", Status);
        ExFreePool(msg);
        return Status;
    }

    ExFreePool(msg);

    return Status;
}

NTSTATUS smb_file::set_rename_information(PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    auto fri = (PFILE_RENAME_INFORMATION)Irp->AssociatedIrp.SystemBuffer;

    // FIXME - do we need to handle fri->RootDirectory?

    if (IrpSp->Parameters.SetFile.FileObject) {
        unsigned int last_backslash;
        FILE_RENAME_INFORMATION_TYPE_2* frit2;
        size_t destlen, frit2len;
        msg_wait mw;
        char* respbuf;
        size_t resp_len;
        UNICODE_STRING new_name;

        // check one of ours
        if (IrpSp->Parameters.SetFile.FileObject->DeviceObject != IrpSp->FileObject->DeviceObject)
            return STATUS_NOT_SAME_DEVICE;

        auto dirobj = CONTAINING_RECORD(IrpSp->Parameters.SetFile.FileObject->FsContext, smb_object, header);

        // check same tree (and hence session and connexion)
        if (dirobj->tree != tree)
            return STATUS_NOT_SAME_DEVICE;

        if (dirobj->type != smb_object_type::file)
            return STATUS_NOT_SAME_DEVICE;

        last_backslash = 0;
        for (unsigned int i = 0; i < fri->FileNameLength / sizeof(WCHAR); i++) {
            if (fri->FileName[i] == '\\')
                last_backslash = i;
        }

        auto dir = static_cast<smb_file*>(dirobj);

        TRACE("new directory is at %.*S\n", dir->name.Length / sizeof(WCHAR), dir->name.Buffer);

        ExAcquireResourceExclusiveLite(&tree->name_lock, true);

        destlen = dir->name.Length + fri->FileNameLength - (last_backslash * sizeof(WCHAR));
        frit2len = offsetof(FILE_RENAME_INFORMATION_TYPE_2, FileName[0]) + destlen;

        frit2 = (FILE_RENAME_INFORMATION_TYPE_2*)ExAllocatePoolWithTag(PagedPool, frit2len, ALLOC_TAG);
        if (!frit2) {
            ERR("out of memory\n");
            ExReleaseResourceLite(&tree->name_lock);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        frit2->ReplaceIfExists = fri->ReplaceIfExists ? 1 : 0;
        RtlZeroMemory(&frit2->Reserved, sizeof(frit2->Reserved));
        frit2->RootDirectory = 0;
        frit2->FileNameLength = destlen;

        RtlCopyMemory(frit2->FileName, dir->name.Buffer, dir->name.Length);
        frit2->FileName[dir->name.Length / sizeof(WCHAR)] = '\\';
        RtlCopyMemory(&frit2->FileName[(dir->name.Length / sizeof(WCHAR)) + 1], &fri->FileName[last_backslash + 1],
                      fri->FileNameLength - (last_backslash * sizeof(WCHAR)) - sizeof(WCHAR));

        TRACE("destination is %.*S\n", frit2->FileNameLength / sizeof(WCHAR), frit2->FileName);

        // doing allocation here, so if we fail it's before the request
        new_name.Length = new_name.MaximumLength = (USHORT)frit2->FileNameLength;
        new_name.Buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, new_name.Length, ALLOC_TAG);
        if (!new_name.Buffer) {
            ERR("out of memory\n");
            ExReleaseResourceLite(&tree->name_lock);
            ExFreePool(frit2);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = send_set_info_msg(SMB2_0_INFO_FILE, IrpSp->Parameters.QueryFile.FileInformationClass,
                                   frit2, frit2len, 0, &mw);
        if (!NT_SUCCESS(Status)) {
            ERR("smb_file::send_query_info_msg returned %08x\n", Status);
            ExReleaseResourceLite(&tree->name_lock);
            ExFreePool(frit2);
            ExFreePool(new_name.Buffer);
            return Status;
        }

        Status = tree->sess->conn->wait_for_response(&mw, &respbuf, &resp_len, Irp);
        if (Status == STATUS_TIMEOUT) {
            ERR("timeout waiting for response\n");
            ExReleaseResourceLite(&tree->name_lock);
            ExFreePool(frit2);
            ExFreePool(new_name.Buffer);
            return Status;
        } else if (!NT_SUCCESS(Status)) {
            ERR("wait_for_response returned %08x\n", Status);
            ExReleaseResourceLite(&tree->name_lock);
            ExFreePool(frit2);
            ExFreePool(new_name.Buffer);
            return Status;
        }

        Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_USER_SESSION_DELETED)
                tree->sess->dead = true;

            ERR("server returned %08x in reply to set information message\n", Status);
            ExReleaseResourceLite(&tree->name_lock);
            ExFreePool(respbuf);
            ExFreePool(frit2);
            ExFreePool(new_name.Buffer);
            return Status;
        }

        // copy new name to object

        RtlCopyMemory(new_name.Buffer, frit2->FileName, new_name.Length);

        if (name.Buffer)
            ExFreePool(name.Buffer);

        name = new_name;

        ExReleaseResourceLite(&tree->name_lock);

        ExFreePool(frit2);

        ExFreePool(respbuf);

        return Status;
    }

    // force Windows to do it manually

    return STATUS_NOT_SAME_DEVICE;
}

NTSTATUS smb_file::set_information(PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    msg_wait mw;
    char* respbuf;
    size_t resp_len;

    TRACE("(%p, %p)\n", this, Irp);

    tree->update_last_activity();

    if (IrpSp->Parameters.SetFile.FileInformationClass == FilePipeInformation) {
        // Just return success - we always return by message anyway.
        return STATUS_SUCCESS;
    } else if (IrpSp->Parameters.SetFile.FileInformationClass == FileRenameInformation)
        return set_rename_information(Irp);

    Status = send_set_info_msg(SMB2_0_INFO_FILE, IrpSp->Parameters.QueryFile.FileInformationClass,
                               Irp->AssociatedIrp.SystemBuffer, IrpSp->Parameters.SetFile.Length, 0, &mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_file::send_query_info_msg returned %08x\n", Status);
        return Status;
    }

    Status = tree->sess->conn->wait_for_response(&mw, &respbuf, &resp_len, Irp);
    if (Status == STATUS_TIMEOUT) {
        ERR("timeout waiting for response\n");
        return Status;
    } else if (!NT_SUCCESS(Status)) {
        ERR("wait_for_response returned %08x\n", Status);
        return Status;
    }

    Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_USER_SESSION_DELETED)
            tree->sess->dead = true;

        ERR("server returned %08x in reply to set information message\n", Status);
        ExFreePool(respbuf);
        return Status;
    }

    ExFreePool(respbuf);

    return Status;
}

NTSTATUS smb_file::query_volume_information(PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    char* respbuf;
    size_t resp_len;
    msg_wait mw;

    TRACE("(%p, %p)\n", this, Irp);

    tree->update_last_activity();

    Status = send_query_info_msg(SMB2_0_INFO_FILESYSTEM, IrpSp->Parameters.QueryVolume.FsInformationClass,
                                 IrpSp->Parameters.QueryVolume.Length, 0, &mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_file::send_query_info_msg returned %08x\n", Status);
        return Status;
    }

    Status = tree->sess->conn->wait_for_response(&mw, &respbuf, &resp_len, Irp);
    if (Status == STATUS_TIMEOUT) {
        ERR("timeout waiting for response\n");
        return Status;
    } else if (!NT_SUCCESS(Status)) {
        ERR("wait_for_response returned %08x\n", Status);
        return Status;
    }

    Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW) {
        if (Status == STATUS_USER_SESSION_DELETED)
            tree->sess->dead = true;

        ERR("server returned %08x in reply to query volume information message\n", Status);
        ExFreePool(respbuf);
        return Status;
    }

    if (resp_len < sizeof(smb2_query_info_response) - sizeof(uint32_t)) {
        ERR("response was %u bytes, expected at least %u\n", resp_len, sizeof(smb2_query_info_response) - sizeof(uint32_t));
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    auto resp = reinterpret_cast<smb2_query_info_response*>(respbuf);

    if (resp->OutputBufferOffset >= (uint16_t)resp_len || resp->OutputBufferOffset + resp->OutputBufferLength >= (uint16_t)resp_len) {
        ERR("invalid offsets in response\n");
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    if (resp->OutputBufferLength > IrpSp->Parameters.QueryVolume.Length) {
        ERR("buffer returned was %u bytes, despite maximum being %u\n", resp->OutputBufferLength, IrpSp->Parameters.QueryVolume.Length);
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, (uint8_t*)resp + sizeof(uint32_t) + resp->OutputBufferOffset, resp->OutputBufferLength);

    Irp->IoStatus.Information = resp->OutputBufferLength;

    ExFreePool(respbuf);

    return Status;
}

void smb_file::purge_cache() {
    CcPurgeCacheSection(&nonpaged->segment_object, nullptr, 0, false);
}

NTSTATUS smb_file::query_security(PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    char* respbuf;
    size_t resp_len;
    msg_wait mw;

    TRACE("(%p, %p)\n", this, Irp);

    tree->update_last_activity();

    Status = send_query_info_msg(SMB2_0_INFO_SECURITY, 0, IrpSp->Parameters.QuerySecurity.Length,
                                 IrpSp->Parameters.QuerySecurity.SecurityInformation, &mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_file::send_query_info_msg returned %08x\n", Status);
        return Status;
    }

    Status = tree->sess->conn->wait_for_response(&mw, &respbuf, &resp_len, Irp);
    if (Status == STATUS_TIMEOUT) {
        ERR("timeout waiting for response\n");
        return Status;
    } else if (!NT_SUCCESS(Status)) {
        ERR("wait_for_response returned %08x\n", Status);
        return Status;
    }

    Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW) {
        if (Status == STATUS_USER_SESSION_DELETED)
            tree->sess->dead = true;

        ERR("server returned %08x in reply to query security message\n", Status);
        ExFreePool(respbuf);
        return Status;
    }

    if (resp_len < sizeof(smb2_query_info_response) - sizeof(uint32_t)) {
        ERR("response was %u bytes, expected at least %u\n", resp_len, sizeof(smb2_query_info_response) - sizeof(uint32_t));
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    auto resp = reinterpret_cast<smb2_query_info_response*>(respbuf);

    if (resp->OutputBufferOffset >= (uint16_t)resp_len || resp->OutputBufferOffset + resp->OutputBufferLength >= (uint16_t)resp_len) {
        ERR("invalid offsets in response\n");
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    if (resp->OutputBufferLength > IrpSp->Parameters.QuerySecurity.Length) {
        ERR("buffer returned was %u bytes, despite maximum being %u\n", resp->OutputBufferLength, IrpSp->Parameters.QuerySecurity.Length);
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(Irp->UserBuffer, (uint8_t*)resp + sizeof(uint32_t) + resp->OutputBufferOffset, resp->OutputBufferLength);

    Irp->IoStatus.Information = resp->OutputBufferLength;

    ExFreePool(respbuf);

    return Status;
}

NTSTATUS smb_file::set_security(PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    msg_wait mw;
    char* respbuf;
    size_t resp_len;

    TRACE("(%p, %p)\n", this, Irp);

    tree->update_last_activity();

    Status = send_set_info_msg(SMB2_0_INFO_SECURITY, 0, IrpSp->Parameters.SetSecurity.SecurityDescriptor,
                               RtlLengthSecurityDescriptor(IrpSp->Parameters.SetSecurity.SecurityDescriptor),
                               IrpSp->Parameters.SetSecurity.SecurityInformation, &mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_file::send_query_info_msg returned %08x\n", Status);
        return Status;
    }

    Status = tree->sess->conn->wait_for_response(&mw, &respbuf, &resp_len, Irp);
    if (Status == STATUS_TIMEOUT) {
        ERR("timeout waiting for response\n");
        return Status;
    } else if (!NT_SUCCESS(Status)) {
        ERR("wait_for_response returned %08x\n", Status);
        return Status;
    }

    Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_USER_SESSION_DELETED)
            tree->sess->dead = true;

        ERR("server returned %08x in reply to set security message\n", Status);
        ExFreePool(respbuf);
        return Status;
    }

    ExFreePool(respbuf);

    return Status;
}

NTSTATUS smb_file::send_lock_msg(uint16_t count, SMB2_LOCK_ELEMENT* elements, msg_wait* mw) {
    size_t msg_len = sizeof(smb2_lock_request) + (count * sizeof(SMB2_LOCK_ELEMENT));
    NTSTATUS Status;

    auto msg = (smb2_lock_request*)ExAllocatePoolWithTag(PagedPool, msg_len, ALLOC_TAG);

    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    tree->sess->conn->setup_smb2_header(msg, msg_len, tree->sess->session_id, tree->tree_id);

    msg->Command = SMB2_OP_LOCK;

    msg->StructureSize = sizeof(smb2_lock_request) - sizeof(smb2_header) + sizeof(SMB2_LOCK_ELEMENT);

    msg->LockCount = count;
    msg->LockSequenceNumber = 0;
    msg->LockSequenceIndex = 0;
    msg->FileId = FileId;

    RtlCopyMemory((uint8_t*)msg + sizeof(smb2_lock_request), elements, count * sizeof(SMB2_LOCK_ELEMENT));

    Status = tree->sess->conn->send(msg, msg_len, mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_connexion::send returned %08x\n", Status);
        ExFreePool(msg);
        return Status;
    }

    ExFreePool(msg);

    return Status;
}

NTSTATUS smb_file::lock(PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    msg_wait mw;
    char* respbuf;
    size_t resp_len;
    smb_lock* l = nullptr;

    /* FIXME - should we use an ERESOURCE rather than a spin lock? There's a gap between
     * populating the SMB2_LOCK_ELEMENT list and sorting out nonpaged->locks. */

    TRACE("(%p, %p)\n", this, Irp);

    tree->update_last_activity();

    switch (IrpSp->MinorFunction) {
        case IRP_MN_LOCK:
        {
            SMB2_LOCK_ELEMENT sle;

            l = (smb_lock*)ExAllocatePoolWithTag(NonPagedPool, sizeof(smb_lock), ALLOC_TAG);
            if (!l) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            sle.Offset = IrpSp->Parameters.LockControl.ByteOffset.QuadPart;
            sle.Length = IrpSp->Parameters.LockControl.Length ? IrpSp->Parameters.LockControl.Length->QuadPart : 0;
            sle.Reserved = 0;

            sle.Flags = IrpSp->Flags & SL_EXCLUSIVE_LOCK ? SMB2_LOCKFLAG_EXCLUSIVE_LOCK : SMB2_LOCKFLAG_SHARED_LOCK;

            if (IrpSp->Flags & SL_FAIL_IMMEDIATELY)
                sle.Flags |= SMB2_LOCKFLAG_FAIL_IMMEDIATELY;

            Status = send_lock_msg(1, &sle, &mw);
            break;
        }

        case IRP_MN_UNLOCK_SINGLE:
        {
            SMB2_LOCK_ELEMENT sle;

            sle.Offset = IrpSp->Parameters.LockControl.ByteOffset.QuadPart;
            sle.Length = IrpSp->Parameters.LockControl.Length ? IrpSp->Parameters.LockControl.Length->QuadPart : 0;
            sle.Reserved = 0;
            sle.Flags = SMB2_LOCKFLAG_UNLOCK;

            Status = send_lock_msg(1, &sle, &mw);
            break;
        }

        case IRP_MN_UNLOCK_ALL:
        case IRP_MN_UNLOCK_ALL_BY_KEY:
        {
            auto minor = IrpSp->MinorFunction;
            auto np = nonpaged;
            auto key = IrpSp->Parameters.LockControl.Key;
            KIRQL irql;
            uint16_t count = 0, i = 0;

            KeAcquireSpinLock(&np->locks_spinlock, &irql);

            LIST_ENTRY* le = np->locks.Flink;
            while (le != &np->locks) {
                auto lock = CONTAINING_RECORD(le, smb_lock, list_entry);

                if (minor == IRP_MN_UNLOCK_ALL || lock->key == key)
                    count++;

                le = le->Flink;
            }

            if (count == 0) {
                KeReleaseSpinLock(&np->locks_spinlock, irql);
                TRACE("no locks matched, returning STATUS_SUCCESS\n");
                return STATUS_SUCCESS;
            }

            auto sle = (SMB2_LOCK_ELEMENT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(SMB2_LOCK_ELEMENT) * count, ALLOC_TAG);
            if (!sle) {
                KeReleaseSpinLock(&np->locks_spinlock, irql);
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            le = np->locks.Flink;
            while (le != &np->locks) {
                auto lock = CONTAINING_RECORD(le, smb_lock, list_entry);

                if (minor == IRP_MN_UNLOCK_ALL || lock->key == key) {
                    sle[i].Offset = lock->offset;
                    sle[i].Length = lock->length;
                    sle[i].Reserved = 0;
                    sle[i].Flags = SMB2_LOCKFLAG_UNLOCK;

                    i++;
                }

                le = le->Flink;
            }

            KeReleaseSpinLock(&np->locks_spinlock, irql);

            Status = send_lock_msg(count, sle, &mw);

            ExFreePool(sle);

            break;
        }

        default:
            ERR("unexpected minor type %x\n", IrpSp->MinorFunction);
            return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (!NT_SUCCESS(Status)) {
        ERR("smb_file::send_lock_msg returned %08x\n", Status);

        if (l)
            ExFreePool(l);

        return Status;
    }

    Status = tree->sess->conn->wait_for_response(&mw, &respbuf, &resp_len, Irp);
    if (Status == STATUS_TIMEOUT) {
        ERR("timeout waiting for response\n");

        if (l)
            ExFreePool(l);

        return Status;
    } else if (!NT_SUCCESS(Status)) {
        ERR("wait_for_response returned %08x\n", Status);

        if (l)
            ExFreePool(l);

        return Status;
    }

    Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_USER_SESSION_DELETED)
            tree->sess->dead = true;

        ERR("server returned %08x in reply to lock message\n", Status);
        ExFreePool(respbuf);

        if (l)
            ExFreePool(l);

        return Status;
    }

    ExFreePool(respbuf);

    switch (IrpSp->MinorFunction) {
        case IRP_MN_LOCK:
        {
            KIRQL irql;
            auto np = nonpaged;

            l->offset = IrpSp->Parameters.LockControl.ByteOffset.QuadPart;
            l->length = IrpSp->Parameters.LockControl.Length ? IrpSp->Parameters.LockControl.Length->QuadPart : 0;
            l->key = IrpSp->Parameters.LockControl.Key;

            KeAcquireSpinLock(&np->locks_spinlock, &irql);
            InsertTailList(&np->locks, &l->list_entry);
            KeReleaseSpinLock(&np->locks_spinlock, irql);

            break;
        }

        case IRP_MN_UNLOCK_SINGLE:
        {
            KIRQL irql;
            auto np = nonpaged;
            auto offset = IrpSp->Parameters.LockControl.ByteOffset.QuadPart;
            auto length = IrpSp->Parameters.LockControl.Length ? IrpSp->Parameters.LockControl.Length->QuadPart : 0ll;

            KeAcquireSpinLock(&np->locks_spinlock, &irql);

            LIST_ENTRY* le = np->locks.Flink;
            while (le != &np->locks) {
                auto lock = CONTAINING_RECORD(le, smb_lock, list_entry);

                if (lock->offset == (uint64_t)offset && lock->length == (uint64_t)length) {
                    RemoveEntryList(&lock->list_entry);
                    ExFreePool(lock);
                    break;
                }

                le = le->Flink;
            }

            KeReleaseSpinLock(&np->locks_spinlock, irql);

            break;
        }

        case IRP_MN_UNLOCK_ALL:
        {
            KIRQL irql;
            auto np = nonpaged;

            KeAcquireSpinLock(&np->locks_spinlock, &irql);

            while (IsListEmpty(&np->locks)) {
                auto lock = CONTAINING_RECORD(RemoveHeadList(&np->locks), smb_lock, list_entry);

                ExFreePool(lock);
            }

            KeReleaseSpinLock(&np->locks_spinlock, irql);

            break;
        }

        case IRP_MN_UNLOCK_ALL_BY_KEY:
        {
            KIRQL irql;
            auto np = nonpaged;
            auto key = IrpSp->Parameters.LockControl.Key;

            KeAcquireSpinLock(&np->locks_spinlock, &irql);

            LIST_ENTRY* le = np->locks.Flink;
            while (le != &np->locks) {
                auto le2 = le->Flink;
                auto lock = CONTAINING_RECORD(le, smb_lock, list_entry);

                if (lock->key == key) {
                    RemoveEntryList(&lock->list_entry);
                    ExFreePool(lock);
                }

                le = le2;
            }

            KeReleaseSpinLock(&np->locks_spinlock, irql);

            break;
        }
    }

    return Status;
}

NTSTATUS smb_file::send_flush_msg(msg_wait* mw) {
    size_t msg_len = sizeof(smb2_flush_request);
    NTSTATUS Status;

    auto msg = (smb2_flush_request*)ExAllocatePoolWithTag(PagedPool, msg_len, ALLOC_TAG);

    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    tree->sess->conn->setup_smb2_header(msg, msg_len, tree->sess->session_id, tree->tree_id);

    msg->Command = SMB2_OP_FLUSH;

    msg->StructureSize = sizeof(smb2_flush_request) - sizeof(smb2_header);
    msg->Reserved1 = 0;
    msg->Reserved2 = 0;
    msg->FileId = FileId;

    Status = tree->sess->conn->send(msg, msg_len, mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_connexion::send returned %08x\n", Status);
        ExFreePool(msg);
        return Status;
    }

    ExFreePool(msg);

    return Status;
}

NTSTATUS smb_file::flush(PIRP Irp) {
    msg_wait mw;
    char* respbuf;
    size_t resp_len;

    TRACE("(%p, %p)\n", this, Irp);

    // FIXME - do CcFlushCache etc. first

    tree->update_last_activity();

    Status = send_flush_msg(&mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_file::send_flush_msg returned %08x\n", Status);
        return Status;
    }

    Status = tree->sess->conn->wait_for_response(&mw, &respbuf, &resp_len, Irp);
    if (Status == STATUS_TIMEOUT) {
        ERR("timeout waiting for response\n");
        return Status;
    } else if (!NT_SUCCESS(Status)) {
        ERR("wait_for_response returned %08x\n", Status);
        return Status;
    }

    Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_USER_SESSION_DELETED)
            tree->sess->dead = true;

        ERR("server returned %08x in reply to flush message\n", Status);
        ExFreePool(respbuf);
        return Status;
    }

    ExFreePool(respbuf);

    return Status;
}
