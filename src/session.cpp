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
#include <winerror.h>

static const WCHAR pipe[] = L"PIPE";
static const WCHAR ipc[] = L"IPC$";

static const int64_t SESSION_AGE = 30; // number of seconds before inactive session gets reaped

NTSTATUS smb_session::setup_session() {
    UNICODE_STRING package;
    CredHandle cred_handle;
    TimeStamp timestamp;
    NTSTATUS Status;
    SECURITY_STATUS sec_status;
    CtxtHandle context;
    SecBufferDesc out;
    SecBuffer outbuf;
    unsigned long context_attr;

    RtlInitUnicodeString(&package, L"NTLM");

    sec_status = AcquireCredentialsHandleW(nullptr, &package, SECPKG_CRED_OUTBOUND, nullptr, nullptr, nullptr,
                                           nullptr, &cred_handle, &timestamp);

    if (FAILED(sec_status)) {
        ERR("AcquireCredentialsHandleW returned %08x\n", sec_status);
        return STATUS_INTERNAL_ERROR;
    }

    outbuf.cbBuffer = 0;
    outbuf.BufferType = SECBUFFER_TOKEN;
    outbuf.pvBuffer = nullptr;

    out.ulVersion = SECBUFFER_VERSION;
    out.cBuffers = 1;
    out.pBuffers = &outbuf;

    sec_status = InitializeSecurityContextW(&cred_handle, nullptr, nullptr, ISC_REQ_ALLOCATE_MEMORY, 0, SECURITY_NATIVE_DREP,
                                            nullptr, 0, &context, &out, &context_attr, nullptr);

    if (FAILED(sec_status)) {
        ERR("InitializeSecurityContextW returned %08x\n", sec_status);
        FreeCredentialsHandle(&cred_handle);
        Status = STATUS_INTERNAL_ERROR;
        goto end;
    }

    // FIXME - SEC_I_COMPLETE_AND_CONTINUE
    // FIXME - SEC_I_COMPLETE_NEEDED

    if (sec_status == SEC_I_CONTINUE_NEEDED) {
        char* respbuf;
        size_t resp_len;
        msg_wait mw;

        Status = conn->send_setup_session_request(&outbuf, 0, &mw);
        if (!NT_SUCCESS(Status)) {
            ERR("send_setup_session_request returned %08x\n", Status);
            goto end2;
        }

        Status = conn->wait_for_response(&mw, &respbuf, &resp_len, nullptr);
        if (Status == STATUS_TIMEOUT) {
            ERR("timeout waiting for response\n");
            goto end2;
        } else if (!NT_SUCCESS(Status)) {
            ERR("wait_for_response returned %08x\n", Status);
            goto end2;
        }

        Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

        if (!NT_SUCCESS(Status) && Status != STATUS_MORE_PROCESSING_REQUIRED) {
            if (Status == STATUS_USER_SESSION_DELETED)
                dead = true;

            ERR("server returned %08x in reply to session setup message\n", Status);
            ExFreePool(respbuf);
            goto end2;
        }

        if (resp_len < sizeof(smb2_session_setup_response) - sizeof(uint32_t)) {
            ERR("response was %u bytes, expected at least %u\n", resp_len, sizeof(smb2_negotiate_response) - sizeof(uint32_t));
            ExFreePool(respbuf);
            Status = STATUS_INVALID_PARAMETER;
            goto end2;
        }

        auto resp = reinterpret_cast<smb2_session_setup_response*>(respbuf);

        if (resp->SecurityBufferOffset >= (uint16_t)resp_len || resp->SecurityBufferOffset + resp->SecurityBufferLength >= (uint16_t)resp_len) {
            ERR("invalid offsets in response\n");
            ExFreePool(respbuf);
            Status = STATUS_INVALID_PARAMETER;
            goto end2;
        }

        // FIXME - test with Kerberos
        // FIXME - how do password prompts work?

        if (Status == STATUS_MORE_PROCESSING_REQUIRED) {
            SecBuffer inbuf;
            SecBufferDesc in;
            msg_wait mw;

            if (resp->SecurityBufferLength == 0) {
                ERR("STATUS_MORE_PROCESSING_REQUIRED returned, but no buffer given\n");
                ExFreePool(respbuf);
                Status = STATUS_INVALID_PARAMETER;
                goto end2;
            }

            if (outbuf.pvBuffer) {
                FreeContextBuffer(outbuf.pvBuffer);
                outbuf.pvBuffer = nullptr;
                outbuf.cbBuffer = 0;
            }

            inbuf.cbBuffer = resp->SecurityBufferLength;
            inbuf.BufferType = SECBUFFER_TOKEN;
            inbuf.pvBuffer = (uint8_t*)resp + sizeof(uint32_t) + resp->SecurityBufferOffset;

            in.ulVersion = SECBUFFER_VERSION;
            in.cBuffers = 1;
            in.pBuffers = &inbuf;

            sec_status = InitializeSecurityContextW(&cred_handle, &context, nullptr, ISC_REQ_ALLOCATE_MEMORY, 0, SECURITY_NATIVE_DREP,
                                                    &in, 0, &context, &out, &context_attr, nullptr);

            if (FAILED(sec_status)) {
                ERR("InitializeSecurityContextW returned %08x\n", sec_status);
                ExFreePool(respbuf);
                Status = sec_status;
                goto end;
            }

            session_id = resp->SessionId;

            ExFreePool(respbuf);

            Status = conn->send_setup_session_request(&outbuf, session_id, &mw);
            if (!NT_SUCCESS(Status)) {
                ERR("send_setup_session_request returned %08x\n", Status);
                goto end2;
            }

            Status = conn->wait_for_response(&mw, &respbuf, &resp_len, nullptr);
            if (Status == STATUS_TIMEOUT) {
                ERR("timeout waiting for response\n");
                goto end2;
            } else if (!NT_SUCCESS(Status)) {
                ERR("wait_for_response returned %08x\n", Status);
                goto end2;
            }

            Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

            if (!NT_SUCCESS(Status)) {
                if (Status == STATUS_USER_SESSION_DELETED)
                    dead = true;

                ERR("server returned %08x in reply to second session setup message\n", Status);
                ExFreePool(respbuf);
                goto end2;
            }
        }

        ExFreePool(respbuf);
    } else {
        FIXME("unhandled security status %08x\n", sec_status);

        Status = STATUS_INTERNAL_ERROR;
    }

end2:
    if (outbuf.pvBuffer)
        FreeContextBuffer(outbuf.pvBuffer);

    DeleteSecurityContext(&context);

end:
    FreeCredentialsHandle(&cred_handle);

    return Status;
}

void smb_session::update_last_activity(uint64_t t) {
    if (t != 0)
        last_activity = t;
    else {
        LARGE_INTEGER time;

        KeQuerySystemTime(&time);

        last_activity = time.QuadPart;
    }

    conn->update_last_activity(last_activity);
}

smb_session::smb_session(smb_connexion* conn, PSID sid) {
    ULONG sid_length;

    InitializeListHead(&trees);
    ExInitializeResourceLite(&tree_lock);

    InterlockedIncrement(&conn->refcount);
    this->conn = conn;

    // copy SID

    sid_length = RtlLengthSid(sid);

    this->sid = ExAllocatePoolWithTag(NonPagedPool, sid_length, ALLOC_TAG);
    if (!this->sid) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        return;
    }

    RtlCopyMemory(this->sid, sid, sid_length);

    Status = setup_session();
    if (!NT_SUCCESS(Status))
        ERR("smb_session::setup_session returned %08x\n", Status);

    update_last_activity();
}

smb_session::~smb_session() {
    shutting_down = true;

    ExAcquireResourceExclusiveLite(&tree_lock, true);

    while (!IsListEmpty(&trees)) {
        auto t = CONTAINING_RECORD(RemoveHeadList(&trees), smb_tree, list_entry);

        t->smb_tree::~smb_tree();
        ExFreePool(t);
    }

    ExReleaseResourceLite(&tree_lock);

    ExDeleteResourceLite(&tree_lock);

    if (sid)
        ExFreePool(sid);

    InterlockedDecrement(&conn->refcount);
}

NTSTATUS smb_session::add_tree(PUNICODE_STRING name, smb_tree** tree) {
    LIST_ENTRY* le;
    UNICODE_STRING pipeus, ipcus;

    if (shutting_down)
        return STATUS_TOO_LATE;

    // If we get "PIPE", change it to "IPC$"

    pipeus.Buffer = (WCHAR*)pipe;
    pipeus.Length = pipeus.MaximumLength = sizeof(pipe) - sizeof(WCHAR);

    if (!RtlCompareUnicodeString(name, &pipeus, true)) {
        ipcus.Buffer = (WCHAR*)ipc;
        ipcus.Length = ipcus.MaximumLength = sizeof(ipc) - sizeof(WCHAR);

        name = &ipcus;
    }

    ExAcquireResourceSharedLite(&tree_lock, true);

    le = trees.Flink;

    while (le != &trees) {
        auto t = CONTAINING_RECORD(le, smb_tree, list_entry);

        if (!RtlCompareUnicodeString(name, &t->name, true)) {
            InterlockedIncrement(&t->refcount);
            *tree = t;
            ExReleaseResourceLite(&tree_lock);

            return STATUS_SUCCESS;
        }

        le = le->Flink;
    }

    ExReleaseResourceLite(&tree_lock);

    ExAcquireResourceExclusiveLite(&tree_lock, true);

    // check again

    le = trees.Flink;

    while (le != &trees) {
        auto t = CONTAINING_RECORD(le, smb_tree, list_entry);

        if (!RtlCompareUnicodeString(name, &t->name, true)) {
            InterlockedIncrement(&t->refcount);
            *tree = t;
            ExReleaseResourceLite(&tree_lock);

            return STATUS_SUCCESS;
        }

        le = le->Flink;
    }

    // still not found, create new

    auto t = (smb_tree*)ExAllocatePoolWithTag(NonPagedPool, sizeof(smb_tree), ALLOC_TAG);
    if (!t) {
        ERR("out of memory\n");
        ExReleaseResourceLite(&tree_lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    new (t) smb_tree(this, name);

    if (!NT_SUCCESS(t->Status)) {
        Status = t->Status;

        ExReleaseResourceLite(&tree_lock);

        ERR("smb_tree::smb_tree returned %08x\n", Status);

        t->smb_tree::~smb_tree();
        ExFreePool(t);
        return Status;
    }

    InsertTailList(&trees, &t->list_entry);

    ExReleaseResourceLite(&tree_lock);

    *tree = t;

    return STATUS_SUCCESS;
}

NTSTATUS smb_session::create_file(PIRP Irp, PUNICODE_STRING filename) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    UNICODE_STRING tree_name, fn;
    smb_tree* t;

    TRACE("(%p, %.*S)\n", Irp, filename->Length / sizeof(WCHAR), filename->Buffer);

    update_last_activity();

    tree_name.Buffer = filename->Buffer;
    tree_name.Length = tree_name.MaximumLength = filename->Length;

    // remove trailing slash
    if (tree_name.Length >= sizeof(WCHAR) && tree_name.Buffer[(tree_name.Length / sizeof(WCHAR)) - 1] == '\\') {
        tree_name.Length -= sizeof(WCHAR);
        tree_name.MaximumLength -= sizeof(WCHAR);
    }

    // remove trailing name if SL_OPEN_TARGET_DIRECTORY set
    if (IrpSp->Flags & SL_OPEN_TARGET_DIRECTORY && tree_name.Length >= sizeof(WCHAR)) {
        for (unsigned int i = (tree_name.Length / sizeof(WCHAR)) - 1; i > 0; i--) {
            if (tree_name.Buffer[i] == '\\') {
                tree_name.Length = tree_name.MaximumLength = i * sizeof(WCHAR);
                break;
            }
        }
    }

    fn.Buffer = nullptr;
    fn.Length = fn.MaximumLength = 0;

    for (unsigned int i = 0; i < tree_name.Length / sizeof(WCHAR); i++) {
        if (tree_name.Buffer[i] == '\\') {
            fn.Length = fn.MaximumLength = tree_name.Length - (i * sizeof(WCHAR)) - sizeof(WCHAR);
            fn.Buffer = &tree_name.Buffer[i + 1];

            tree_name.Length = tree_name.MaximumLength = i * sizeof(WCHAR);

            break;
        }
    }

    if (tree_name.Length == 0)
        return STATUS_OBJECT_PATH_INVALID;

    Status = add_tree(&tree_name, &t);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_session::add_tree returned %08x\n", Status);
        return Status;
    }

    Status = t->create_file(Irp, &fn);
    if (!NT_SUCCESS(Status))
        ERR("smb_tree::create_file returned %08x\n", Status);

    t->update_last_activity();

    InterlockedDecrement(&t->refcount);

    return Status;
}

void smb_session::purge_cache() {
    LIST_ENTRY* le;

    ExAcquireResourceSharedLite(&tree_lock, true);

    le = trees.Flink;
    while (le != &trees) {
        auto tree = CONTAINING_RECORD(le, smb_tree, list_entry);

        tree->purge_cache();

        le = le->Flink;
    }

    ExReleaseResourceLite(&tree_lock);
}

void smb_session::reap_trees() {
    LARGE_INTEGER time;

    time.QuadPart = 0;

    ExAcquireResourceExclusiveLite(&tree_lock, true);

    LIST_ENTRY* le = trees.Flink;

    while (le != &trees) {
        auto le2 = le->Flink;
        auto t = CONTAINING_RECORD(le, smb_tree, list_entry);

        if (t->refcount == 0) {
            if (time.QuadPart == 0)
                KeQuerySystemTime(&time);

            if (t->try_to_reap(time.QuadPart)) {
                RemoveEntryList(&t->list_entry);
                t->smb_tree::~smb_tree();
                ExFreePool(t);
            }
        }

        le = le2;
    }

    ExReleaseResourceLite(&tree_lock);
}

NTSTATUS smb_session::send_logoff_msg(msg_wait* mw) {
    size_t msg_len = sizeof(smb2_logoff_request);
    NTSTATUS Status;

    auto msg = (smb2_logoff_request*)ExAllocatePoolWithTag(PagedPool, msg_len, ALLOC_TAG);

    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    conn->setup_smb2_header(msg, msg_len, session_id, 0);

    msg->Command = SMB2_OP_LOGOFF;

    msg->StructureSize = sizeof(smb2_logoff_request) - sizeof(smb2_header);
    msg->Reserved = 0;

    Status = conn->send(msg, msg_len, mw, true);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_connexion::send returned %08x\n", Status);
        ExFreePool(msg);
        return Status;
    }

    ExFreePool(msg);

    return Status;
}

bool smb_session::try_to_reap(uint64_t time) {
    ExAcquireResourceExclusiveLite(&tree_lock, true);

    if (refcount > 0) { // refcount has increased since acquiring the lock
        ExReleaseResourceLite(&tree_lock);
        return false;
    }

    if (dead || last_activity + (SESSION_AGE * 10000000ull) <= time) {
        msg_wait mw;
        NTSTATUS Status;

        Status = send_logoff_msg(&mw);
        if (!NT_SUCCESS(Status)) {
            ERR("smb_session::send_logoff_msg returned %08x\n", Status);
        } else {
            char* respbuf;
            size_t resp_len;

            Status = conn->wait_for_response(&mw, &respbuf, &resp_len, nullptr);
            if (Status == STATUS_TIMEOUT) {
                ERR("timeout waiting for response\n");
            } else if (!NT_SUCCESS(Status)) {
                ERR("wait_for_response returned %08x\n", Status);
            } else {
                Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

                if (!NT_SUCCESS(Status))
                    ERR("server returned %08x in reply to logoff message\n", Status);

                ExFreePool(respbuf);
            }
        }

        ExReleaseResourceLite(&tree_lock);

        return true;
    }

    ExReleaseResourceLite(&tree_lock);

    return false;
}
