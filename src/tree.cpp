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

static const int64_t TREE_AGE = 30; // number of seconds before inactive tree gets reaped

void smb_tree::update_last_activity() {
    LARGE_INTEGER time;

    KeQuerySystemTime(&time);

    last_activity = time.QuadPart;

    sess->update_last_activity(time.QuadPart);
}

smb_tree::smb_tree(smb_session* sess, PUNICODE_STRING name) {
    InterlockedIncrement(&sess->refcount);
    this->sess = sess;

    this->name.Length = this->name.MaximumLength = name->Length;

    if (name->Length == 0)
        this->name.Buffer = nullptr;
    else {
        this->name.Buffer = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, name->Length, ALLOC_TAG);
        if (!this->name.Buffer) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            return;
        }

        RtlCopyMemory(this->name.Buffer, name->Buffer, name->Length);
    }

    InitializeListHead(&files);
    ExInitializeResourceLite(&file_lock);

    ExInitializeResourceLite(&name_lock);

    Status = tree_connect();
    if (!NT_SUCCESS(Status))
        ERR("smb_tree::tree_connect returned %08x\n", Status);

    update_last_activity();
}

smb_tree::~smb_tree() {
    shutting_down = true;

    ExAcquireResourceExclusiveLite(&file_lock, true);

    while (!IsListEmpty(&files)) {
        auto f = CONTAINING_RECORD(RemoveHeadList(&files), smb_object, list_entry);

        switch (f->type) {
            case smb_object_type::file:
                static_cast<smb_file*>(f)->smb_file::~smb_file();
            break;

            case smb_object_type::pipe:
                static_cast<smb_pipe*>(f)->smb_pipe::~smb_pipe();
            break;
        }

        ExFreePool(f);
    }

    ExReleaseResourceLite(&file_lock);

    ExDeleteResourceLite(&file_lock);

    ExDeleteResourceLite(&name_lock);

    if (name.Buffer)
        ExFreePool(name.Buffer);

    InterlockedDecrement(&sess->refcount);
}

NTSTATUS smb_tree::send_tree_connect_msg(PUNICODE_STRING name, msg_wait* mw) {
    size_t msg_len = sizeof(smb2_tree_connect_request) + name->Length;
    NTSTATUS Status;

    auto msg = (smb2_tree_connect_request*)ExAllocatePoolWithTag(PagedPool, msg_len, ALLOC_TAG);

    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    sess->conn->setup_smb2_header(msg, msg_len, sess->session_id, 0);

    msg->Command = SMB2_OP_TCON;

    msg->StructureSize = (sizeof(smb2_tree_connect_request) - sizeof(smb2_header)) | 1;
    msg->Flags = 0;
    msg->PathOffset = name->Length > 0 ? (sizeof(smb2_tree_connect_request) - sizeof(uint32_t)) : 0;
    msg->PathLength = (uint16_t)name->Length;

    if (name->Length > 0)
        RtlCopyMemory((uint8_t*)msg + msg->PathOffset + sizeof(uint32_t), name->Buffer, name->Length);

    Status = sess->conn->send(msg, msg_len, mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_connexion::send returned %08x\n", Status);
        ExFreePool(msg);
        return Status;
    }

    ExFreePool(msg);

    return Status;
}

NTSTATUS smb_tree::tree_connect() {
    NTSTATUS Status;
    char* respbuf;
    size_t resp_len;
    UNICODE_STRING path;
    msg_wait mw;

    path.Length = path.MaximumLength = (3 * sizeof(WCHAR)) + sess->conn->hostname.Length + name.Length;
    path.Buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, path.Length, ALLOC_TAG);

    if (!path.Buffer) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    path.Buffer[0] = '\\';
    path.Buffer[1] = '\\';
    RtlCopyMemory(&path.Buffer[2], sess->conn->hostname.Buffer, sess->conn->hostname.Length);
    path.Buffer[2 + (sess->conn->hostname.Length / sizeof(WCHAR))] = '\\';
    RtlCopyMemory(&path.Buffer[3 + (sess->conn->hostname.Length / sizeof(WCHAR))], name.Buffer, name.Length);

    Status = send_tree_connect_msg(&path, &mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_tree::send_tree_connect_msg returned %08x\n", Status);
        ExFreePool(path.Buffer);
        return Status;
    }

    ExFreePool(path.Buffer);

    Status = sess->conn->wait_for_response(&mw, &respbuf, &resp_len, nullptr);
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
            sess->dead = true;

        ERR("server returned %08x in reply to tree connexion message\n", Status);
        ExFreePool(respbuf);
        return Status;
    }

    if (resp_len < sizeof(smb2_tree_connect_response) - sizeof(uint32_t)) {
        ERR("response was %u bytes, expected at least %u\n", resp_len, sizeof(smb2_tree_connect_response) - sizeof(uint32_t));
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    auto resp = reinterpret_cast<smb2_tree_connect_response*>(respbuf);

    share_type = resp->ShareType;
    share_flags = resp->ShareFlags;
    capabilities = resp->Capabilities;
    maximal_access = resp->MaximalAccess;

    tree_id = reinterpret_cast<smb2_header*>(respbuf)->TreeId;

    ExFreePool(respbuf);

    return Status;
}

NTSTATUS smb_tree::send_create_file_msg(PUNICODE_STRING name, uint32_t desired_access, uint32_t file_attributes,
                                        uint32_t share_access, uint32_t create_disposition, uint32_t create_options,
                                        msg_wait* mw) {
    TRACE("(%p, %.*S, %x, %x, %x, %x, %x, %p)\n", this, name->Length / sizeof(WCHAR), name->Buffer,
                                                  desired_access, file_attributes, share_access, create_disposition,
                                                  create_options, mw);

    // Samba doesn't like create messages with no dynamic part
    size_t msg_len = sizeof(smb2_create_request) + (name->Length > 0 ? name->Length : 1);
    NTSTATUS Status;

    auto msg = (smb2_create_request*)ExAllocatePoolWithTag(PagedPool, msg_len, ALLOC_TAG);

    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    sess->conn->setup_smb2_header(msg, msg_len, sess->session_id, tree_id);

    msg->Command = SMB2_OP_CREATE;

    msg->StructureSize = (sizeof(smb2_create_request) - sizeof(smb2_header)) | 1;
    msg->SecurityFlags = 0;
    msg->RequestedOplockLevel = 0; // FIXME - support oplocks
    msg->ImpersonationLevel = 1; // "Identification"
    msg->SmbCreateFlags = 0;
    msg->Reserved = 0;
    msg->DesiredAccess = desired_access;
    msg->FileAttributes = file_attributes;
    msg->ShareAccess = share_access;
    msg->CreateDisposition = create_disposition;
    msg->CreateOptions = create_options;
    msg->NameOffset = name->Length > 0 ? (sizeof(smb2_create_request) - sizeof(uint32_t)) : 0;
    msg->NameLength = (uint16_t)name->Length;
    msg->CreateContextsOffset = 0; // FIXME - support create contexts
    msg->CreateContextsLength = 0;

    if (name->Length > 0)
        RtlCopyMemory((uint8_t*)msg + msg->NameOffset + sizeof(uint32_t), name->Buffer, name->Length);

    Status = sess->conn->send(msg, msg_len, mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_connexion::send returned %08x\n", Status);
        ExFreePool(msg);
        return Status;
    }

    ExFreePool(msg);

    return Status;
}

NTSTATUS smb_tree::create_file(PIRP Irp, PUNICODE_STRING filename) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    char* respbuf;
    size_t resp_len;
    msg_wait mw;

    TRACE("(%p, %.*S)\n", Irp, filename->Length / sizeof(WCHAR), filename->Buffer);

    if (shutting_down)
        return STATUS_TOO_LATE;

    if (filename->Length == 0 && share_type == SMB2_SHARE_TYPE_PIPE) {
        auto p = (smb_pipe*)ExAllocatePoolWithTag(PagedPool, sizeof(smb_pipe), ALLOC_TAG);
        if (!p) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        new (p) smb_pipe(this, IrpSp->FileObject);

        if (!NT_SUCCESS(p->Status)) {
            Status = p->Status;

            ERR("smb_pipe::smb_pipe returned %08x\n", Status);
            p->smb_pipe::~smb_pipe();
            ExFreePool(p);

            return Status;
        }

        ExAcquireResourceExclusiveLite(&file_lock, true);
        InsertTailList(&files, &p->list_entry);
        ExReleaseResourceLite(&file_lock);

        Irp->IoStatus.Information = FILE_OPENED;

        IrpSp->FileObject->FsContext = &p->header;

        return STATUS_SUCCESS;
    }

    // FIXME - creation with EAs

    Status = send_create_file_msg(filename, IrpSp->Parameters.Create.SecurityContext->DesiredAccess,
                                  IrpSp->Parameters.Create.FileAttributes, IrpSp->Parameters.Create.ShareAccess, (IrpSp->Parameters.Create.Options >> 24) & 0xff,
                                  IrpSp->Parameters.Create.Options & FILE_VALID_OPTION_FLAGS, &mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_tree::send_create_file_msg returned %08x\n", Status);
        return Status;
    }

    Status = sess->conn->wait_for_response(&mw, &respbuf, &resp_len, Irp);
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
            sess->dead = true;

        ERR("server returned %08x in reply to create message\n", Status);
        ExFreePool(respbuf);
        return Status;
    }

    if (resp_len < sizeof(smb2_create_response) - sizeof(uint32_t)) {
        ERR("response was %u bytes, expected at least %u\n", resp_len, sizeof(smb2_create_response) - sizeof(uint32_t));
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    auto f = (smb_file*)ExAllocatePoolWithTag(PagedPool, sizeof(smb_file), ALLOC_TAG);
    if (!f) {
        ERR("out of memory\n");
        ExFreePool(respbuf);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    new (f) smb_file(this, IrpSp->FileObject, filename, reinterpret_cast<smb2_create_response*>(respbuf));

    if (!NT_SUCCESS(f->Status)) {
        Status = f->Status;

        ERR("smb_file::smb_file returned %08x\n", Status);
        f->smb_file::~smb_file();
        ExFreePool(f);

        return Status;
    }

    ExAcquireResourceExclusiveLite(&file_lock, true);
    InsertTailList(&files, &f->list_entry);
    ExReleaseResourceLite(&file_lock);

    Irp->IoStatus.Information = reinterpret_cast<smb2_create_response*>(respbuf)->CreateAction;

    ExFreePool(respbuf);

    IrpSp->FileObject->FsContext = &f->header;
    IrpSp->FileObject->SectionObjectPointer = &f->nonpaged->segment_object;

    return STATUS_SUCCESS;
}

NTSTATUS smb_tree::close_file(smb_object* obj, PFILE_OBJECT FileObject) {
    NTSTATUS Status;
    bool locked = false;

    Status = obj->close(FileObject);
    if (!NT_SUCCESS(Status))
        ERR("smb_object::close returned %08x\n", Status);

    if (!ExIsResourceAcquiredExclusiveLite(&file_lock)) {
        ExAcquireResourceExclusiveLite(&file_lock, true);
        locked = true;
    }

    RemoveEntryList(&obj->list_entry);

    switch (obj->type) {
        case smb_object_type::file:
            static_cast<smb_file*>(obj)->smb_file::~smb_file();
            break;

        case smb_object_type::pipe:
            static_cast<smb_pipe*>(obj)->smb_pipe::~smb_pipe();
            break;
    }

    ExFreePool(obj);

    if (locked)
        ExReleaseResourceLite(&file_lock);

    return Status;
}

void smb_tree::purge_cache() {
    LIST_ENTRY* le;

    ExAcquireResourceExclusiveLite(&file_lock, true);

    le = files.Flink;
    while (le != &files) {
        auto obj = CONTAINING_RECORD(le, smb_object, list_entry);

        ObReferenceObject(obj->FileObject);

        le = le->Flink;
    }

    le = files.Flink;
    while (le != &files) {
        auto obj = CONTAINING_RECORD(le, smb_object, list_entry);

        obj->purge_cache();

        le = le->Flink;
    }

    le = files.Flink;
    while (le != &files) {
        auto le2 = le->Flink;
        auto obj = CONTAINING_RECORD(le, smb_object, list_entry);

        ObDereferenceObject(obj->FileObject);

        le = le2;
    }

    ExReleaseResourceLite(&file_lock);
}

NTSTATUS smb_tree::send_tree_disconnect_msg(msg_wait* mw) {
    size_t msg_len = sizeof(smb2_tree_disconnect_request);
    NTSTATUS Status;

    auto msg = (smb2_tree_disconnect_request*)ExAllocatePoolWithTag(PagedPool, msg_len, ALLOC_TAG);

    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    sess->conn->setup_smb2_header(msg, msg_len, sess->session_id, tree_id);

    msg->Command = SMB2_OP_TDIS;

    msg->StructureSize = sizeof(smb2_tree_disconnect_request) - sizeof(smb2_header);
    msg->Reserved = 0;

    Status = sess->conn->send(msg, msg_len, mw, true);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_connexion::send returned %08x\n", Status);
        ExFreePool(msg);
        return Status;
    }

    ExFreePool(msg);

    return Status;
}

bool smb_tree::try_to_reap(uint64_t time) {
    ExAcquireResourceExclusiveLite(&file_lock, true);

    if (refcount > 0) { // refcount has increased since acquiring the lock
        ExReleaseResourceLite(&file_lock);
        return false;
    }

    if (last_activity + (TREE_AGE * 10000000ull) <= time) {
        msg_wait mw;
        NTSTATUS Status;

        Status = send_tree_disconnect_msg(&mw);
        if (!NT_SUCCESS(Status)) {
            ERR("smb_tree::send_tree_disconnect_msg returned %08x\n", Status);
        } else {
            char* respbuf;
            size_t resp_len;

            Status = sess->conn->wait_for_response(&mw, &respbuf, &resp_len, nullptr);
            if (Status == STATUS_TIMEOUT) {
                ERR("timeout waiting for response\n");
            } else if (!NT_SUCCESS(Status)) {
                ERR("wait_for_response returned %08x\n", Status);
            } else {
                Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

                if (Status == STATUS_USER_SESSION_DELETED)
                    sess->dead = true;

                if (!NT_SUCCESS(Status))
                    ERR("server returned %08x in reply to tree disconnect message\n", Status);

                ExFreePool(respbuf);
            }
        }

        ExReleaseResourceLite(&file_lock);

        return true;
    }

    ExReleaseResourceLite(&file_lock);

    return false;
}
