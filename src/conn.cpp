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

// FIXME - other dialects (esp "SMB 2.???")
static const char* protocols[] = {
    "SMB 2.002",
    nullptr
};

extern PDEVICE_OBJECT master_devobj;
extern ERESOURCE connexion_lock;
extern LIST_ENTRY connexion_list;

static const int64_t REAP_THREAD_INTERVAL = 10; // reap thread should run every 10 seconds

void smb_connexion::received_message(char* data, ULONG data_len) {
    TRACE("received message of %u bytes\n", data_len);

    if (data_len < sizeof(smb_header)) {
        ERR("message was too short: %u bytes, expected at least %u\n", data_len, sizeof(smb_header));
        return;
    }

    auto smbh = (smb_header*)data;

    if (smbh->Protocol == SMB2_MAGIC) {
        if (data_len < sizeof(smb2_header)) {
            ERR("SMB2 message was too short: %u bytes, expected at least %u\n", data_len, sizeof(smb1_header));
            return;
        }

        auto smb2h = (smb2_header*)data;

        if (smb2h->Flags & SMB2_HDR_FLAG_REDIRECT) { // reply
            LIST_ENTRY* le;
            uint64_t msg_id = smb2h->MessageId;
            bool success = false;
            KIRQL irql;

            auto resp = (char*)ExAllocatePoolWithTag(NonPagedPool, data_len, ALLOC_TAG);
            if (!resp) {
                ERR("out of memory\n");
                return;
            }

            RtlCopyMemory(resp, data, data_len);

            KeAcquireSpinLock(&msg_waits_spinlock, &irql);

            le = msg_waits.Flink;
            while (le != &msg_waits) {
                auto mw = CONTAINING_RECORD(le, msg_wait, list_entry);

                if (mw->msg_id == msg_id) {
                    mw->resp = resp;
                    mw->resp_len = data_len;
                    KeSetEvent(&mw->event, 0, false);

                    success = true;
                    break;
                }

                le = le->Flink;
            }

            KeReleaseSpinLock(&msg_waits_spinlock, irql);

            if (!success) {
                // FIXME - should return error message
                ERR("received unexpected response to message %I64x\n", msg_id);
                ExFreePool(resp);
            } else
                TRACE("dispatched response to message %I64x\n", msg_id);
        } else {
            ERR("unhandled SMB2 message %x\n", smb2h->Command);
            // FIXME - should send error message
        }
    } else
        ERR("unknown protocol %08x\n", smbh->Protocol);
}

void smb_connexion::send_thread() {
    bool disconnect = false;
    KIRQL irql;

    TRACE("starting send thread\n");

    KeClearEvent(&send_thread_quit_event);

    while (true) {
        void* objs[2];

        objs[0] = &send_msg_event;
        objs[1] = &shutdown_event;

        KeWaitForMultipleObjects(2, objs, WaitAny, Executive, KernelMode, false, nullptr, nullptr);

        if (KeReadStateEvent(&shutdown_event))
            break;

        while (true) {
            KeAcquireSpinLock(&send_msg_spinlock, &irql);

            if (IsListEmpty(&send_msgs)) {
                KeReleaseSpinLock(&send_msg_spinlock, irql);
                break;
            }

            auto sm = CONTAINING_RECORD(RemoveHeadList(&send_msgs), send_msg, list_entry);

            KeReleaseSpinLock(&send_msg_spinlock, irql);

            Status = net_conn.send(sm->data, sm->length);
            if (!NT_SUCCESS(Status)) {
                ERR("tdi::send returned %08x\n", Status);
                ExFreePool(sm);
                disconnect = true;
                break;
            }

            ExFreePool(sm);
        }

        if (disconnect)
            break;
    }

    TRACE("end of send thread\n");

    // clear remaining messages

    KeAcquireSpinLock(&send_msg_spinlock, &irql);

    while (!IsListEmpty(&send_msgs)) {
        auto sm = CONTAINING_RECORD(RemoveHeadList(&send_msgs), send_msg, list_entry);

        ExFreePool(sm);
    }

    KeReleaseSpinLock(&send_msg_spinlock, irql);

    if (disconnect) {
        ExAcquireResourceExclusiveLite(&tdi_lock, true);
        net_conn.tdi::~tdi();
        ExReleaseResourceLite(&tdi_lock);
    }

    ZwClose(send_thread_handle);
    send_thread_handle = nullptr;

    KeSetEvent(&send_thread_quit_event, 0, false);
}

void smb_connexion::reap_thread() {
    KTIMER timer;
    LARGE_INTEGER due_time;

    TRACE("starting reap thread\n");

    KeClearEvent(&reap_thread_quit_event);

    KeInitializeTimer(&timer);

    due_time.QuadPart = REAP_THREAD_INTERVAL * -10000000;

    KeSetTimer(&timer, due_time, nullptr);

    while (true) {
        void* objs[2];
        LARGE_INTEGER time;

        time.QuadPart = 0;

        objs[0] = &timer;
        objs[1] = &shutdown_event;

        KeWaitForMultipleObjects(2, objs, WaitAny, Executive, KernelMode, false, nullptr, nullptr);

        if (KeReadStateEvent(&shutdown_event)) {
            KeCancelTimer(&timer);
            break;
        }

        // free inactive trees

        {
            ExAcquireResourceSharedLite(&session_lock, true);

            LIST_ENTRY* le = sessions.Flink;

            while (le != &sessions) {
                auto sess = CONTAINING_RECORD(le, smb_session, list_entry);

                sess->reap_trees();

                le = le->Flink;
            }

            ExReleaseResourceLite(&session_lock);
        }

        // free dead or inactive sessions

        {
            ExAcquireResourceExclusiveLite(&session_lock, true);

            LIST_ENTRY* le = sessions.Flink;

            while (le != &sessions) {
                auto le2 = le->Flink;
                auto sess = CONTAINING_RECORD(le, smb_session, list_entry);

                if (sess->refcount == 0) {
                    if (time.QuadPart == 0)
                        KeQuerySystemTime(&time);

                    if (sess->try_to_reap(time.QuadPart)) {
                        RemoveEntryList(&sess->list_entry);
                        sess->smb_session::~smb_session();
                        ExFreePool(sess);
                    }
                }

                le = le2;
            }

            ExReleaseResourceLite(&session_lock);
        }

        KeSetTimer(&timer, due_time, nullptr);
    }

    TRACE("end of reap thread\n");

    ZwClose(reap_thread_handle);
    reap_thread_handle = nullptr;

    KeSetEvent(&reap_thread_quit_event, 0, false);
}

void smb_connexion::recv_thread() {
    ULONG retlen;
    NTSTATUS Status;

    KeClearEvent(&recv_thread_quit_event);

    while (true) {
        bool disconnect = false;

        Status = net_conn.recv(buf, sizeof(buf), &retlen, &shutdown_event);
        if (!NT_SUCCESS(Status)) {
            ERR("tdi::recv returned %08x\n", Status);
            break;
        }

        if (KeReadStateEvent(&shutdown_event))
            break;

        if (retlen == 0) {
            ExAcquireResourceExclusiveLite(&tdi_lock, true);

            TRACE("connexion closed\n");
            net_conn.tdi::~tdi();

            ExReleaseResourceLite(&tdi_lock);

            break;
        }

        TRACE("received %u bytes\n", retlen);

        auto buf2 = buf;

        if (partial_msgs_len > 0) {
            auto pm = (char*)ExAllocatePoolWithTag(PagedPool, partial_msgs_len + retlen, ALLOC_TAG);

            if (!pm) {
                ERR("out of memory, disconnecting\n");
                ExAcquireResourceExclusiveLite(&tdi_lock, true);
                net_conn.tdi::~tdi();
                ExReleaseResourceLite(&tdi_lock);
                break;
            }

            RtlCopyMemory(pm, partial_msgs, partial_msgs_len);
            RtlCopyMemory(pm + partial_msgs_len, buf2, retlen);

            partial_msgs_len += retlen;

            ExFreePool(partial_msgs);
            partial_msgs = pm;

            while (partial_msgs_len >= sizeof(uint32_t)) {
                auto msg_len = _byteswap_ulong(*(uint32_t*)partial_msgs);

                if (msg_len & 0xff000000) {
                    ERR("malformed input, disconnecting\n");
                    ExAcquireResourceExclusiveLite(&tdi_lock, true);
                    net_conn.tdi::~tdi();
                    ExReleaseResourceLite(&tdi_lock);

                    disconnect = true;
                    break;
                }

                if (partial_msgs_len >= msg_len + sizeof(uint32_t)) {
                    received_message(partial_msgs, msg_len + sizeof(uint32_t));

                    if (partial_msgs_len == msg_len + sizeof(uint32_t)) {
                        ExFreePool(partial_msgs);
                        partial_msgs = nullptr;
                        partial_msgs_len = 0;
                        break;
                    }

                    auto pm = (char*)ExAllocatePoolWithTag(PagedPool, partial_msgs_len - msg_len - sizeof(uint32_t), ALLOC_TAG);

                    if (!pm) {
                        ERR("out of memory, disconnecting\n");
                        ExAcquireResourceExclusiveLite(&tdi_lock, true);
                        net_conn.tdi::~tdi();
                        ExReleaseResourceLite(&tdi_lock);
                        break;
                    }

                    partial_msgs_len -= msg_len + sizeof(uint32_t);

                    RtlCopyMemory(pm, partial_msgs + msg_len + sizeof(uint32_t), partial_msgs_len);

                    ExFreePool(partial_msgs);
                    partial_msgs = pm;
                } else
                    break;
            }

            if (disconnect)
                break;
        } else {
            while (retlen >= sizeof(uint32_t)) {
                auto msg_len = _byteswap_ulong(*(uint32_t*)buf2);

                if (msg_len & 0xff000000) {
                    ERR("malformed input, disconnecting\n");
                    ExAcquireResourceExclusiveLite(&tdi_lock, true);
                    net_conn.tdi::~tdi();
                    ExReleaseResourceLite(&tdi_lock);

                    disconnect = true;
                    break;
                }

                if (retlen >= msg_len + sizeof(uint32_t)) {
                    received_message(buf2, msg_len + sizeof(uint32_t));

                    buf2 += msg_len + sizeof(uint32_t);
                    retlen -= msg_len + sizeof(uint32_t);
                } else
                    break;
            }

            if (disconnect)
                break;

            if (retlen > 0) { // save any left as partial message
                auto pm = (char*)ExAllocatePoolWithTag(PagedPool, partial_msgs_len + retlen, ALLOC_TAG);

                if (!pm) {
                    ERR("out of memory, disconnecting\n");
                    ExAcquireResourceExclusiveLite(&tdi_lock, true);
                    net_conn.tdi::~tdi();
                    ExReleaseResourceLite(&tdi_lock);
                    break;
                }

                if (partial_msgs_len > 0)
                    RtlCopyMemory(pm, partial_msgs, partial_msgs_len);

                RtlCopyMemory(pm + partial_msgs_len, buf2, retlen);

                partial_msgs_len += retlen;

                if (partial_msgs)
                    ExFreePool(partial_msgs);

                partial_msgs = pm;
            }
        }
    }

    TRACE("end of recv thread\n");

    ZwClose(recv_thread_handle);
    recv_thread_handle = nullptr;

    {
        KIRQL irql;
        LIST_ENTRY* le;

        // cancel pending messages
        KeAcquireSpinLock(&msg_waits_spinlock, &irql);

        le = msg_waits.Flink;
        while (le != &msg_waits) {
            auto mw = CONTAINING_RECORD(le, msg_wait, list_entry);

            mw->resp = nullptr;
            mw->resp_len = 0;
            KeSetEvent(&mw->event, 0, false);

            le = le->Flink;
        }

        KeReleaseSpinLock(&msg_waits_spinlock, irql);
    }

    {
        ExAcquireResourceExclusiveLite(&session_lock, true);
        LIST_ENTRY* le;

        le = sessions.Flink;
        while (le != &sessions) {
            auto sess = CONTAINING_RECORD(le, smb_session, list_entry);

            sess->dead = true;

            le = le->Flink;
        }

        ExReleaseResourceLite(&session_lock);
    }

    KeSetEvent(&recv_thread_quit_event, 0, false);
}

smb_connexion::smb_connexion(PUNICODE_STRING hostname, uint32_t ip_address) : ip_address(ip_address) {
    KeInitializeEvent(&shutdown_event, NotificationEvent, false);
    KeInitializeEvent(&recv_thread_quit_event, NotificationEvent, false);
    ExInitializeResourceLite(&tdi_lock);

    InitializeListHead(&msg_waits);
    KeInitializeSpinLock(&msg_waits_spinlock);

    InitializeListHead(&sessions);
    ExInitializeResourceLite(&session_lock);

    InitializeListHead(&send_msgs);
    KeInitializeSpinLock(&send_msg_spinlock);
    KeInitializeEvent(&send_msg_event, SynchronizationEvent, false);
    KeInitializeEvent(&send_thread_quit_event, NotificationEvent, false);
    KeInitializeEvent(&reap_thread_quit_event, NotificationEvent, false);

    this->hostname.Length = this->hostname.MaximumLength = hostname->Length;
    this->hostname.Buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, hostname->Length, ALLOC_TAG);

    if (!this->hostname.Buffer) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        return;
    }

    RtlCopyMemory(this->hostname.Buffer, hostname->Buffer, hostname->Length);

    Status = STATUS_SUCCESS;
}

smb_connexion::~smb_connexion() {
    shutting_down = true;

    // send signal and wait for threads to quit
    ExAcquireResourceExclusiveLite(&tdi_lock, true);
    KeSetEvent(&shutdown_event, 0, false);
    ExReleaseResourceLite(&tdi_lock);

    if (recv_thread_handle)
        KeWaitForSingleObject(&recv_thread_quit_event, Executive, KernelMode, false, nullptr);

    if (send_thread_handle)
        KeWaitForSingleObject(&send_thread_quit_event, Executive, KernelMode, false, nullptr);

    if (reap_thread_handle)
        KeWaitForSingleObject(&reap_thread_quit_event, Executive, KernelMode, false, nullptr);

    if (partial_msgs)
        ExFreePool(partial_msgs);

    ExAcquireResourceExclusiveLite(&session_lock, true);

    while (!IsListEmpty(&sessions)) {
        auto sess = CONTAINING_RECORD(RemoveHeadList(&sessions), smb_session, list_entry);

        sess->smb_session::~smb_session();
        ExFreePool(sess);
    }

    ExReleaseResourceLite(&session_lock);

    if (hostname.Buffer)
        ExFreePool(hostname.Buffer);

    ExDeleteResourceLite(&tdi_lock);
    ExDeleteResourceLite(&session_lock);
}

NTSTATUS smb_connexion::add_send_msg_to_queue(void* data, ULONG data_len, msg_wait* mw) {
    KIRQL irql;
    uint64_t msg_id;

    auto sm = (send_msg*)ExAllocatePoolWithTag(NonPagedPool, offsetof(send_msg, data[0]) + data_len, ALLOC_TAG);
    if (!sm) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    sm->length = data_len;
    RtlCopyMemory(sm->data, data, data_len);

    mw->msg_id = 0xffffffffffffffff;
    KeInitializeEvent(&mw->event, NotificationEvent, false);

    KeAcquireSpinLock(&msg_waits_spinlock, &irql);
    InsertTailList(&msg_waits, &mw->list_entry);
    KeReleaseSpinLock(&msg_waits_spinlock, irql);

    KeAcquireSpinLock(&send_msg_spinlock, &irql);

    msg_id = InterlockedIncrement64(&next_msg_id);
    mw->msg_id = msg_id;

    reinterpret_cast<smb2_header*>(sm->data)->MessageId = msg_id;

    InsertTailList(&send_msgs, &sm->list_entry);
    KeSetEvent(&send_msg_event, 0, false);

    KeReleaseSpinLock(&send_msg_spinlock, irql);

    return STATUS_SUCCESS;
}

NTSTATUS smb_connexion::send(void* data, ULONG data_len, msg_wait* mw, bool no_reconnect) {
    NTSTATUS Status;

    ExAcquireResourceSharedLite(&tdi_lock, true);

    if (net_conn.init) {
        Status = add_send_msg_to_queue(data, data_len, mw);

        ExReleaseResourceLite(&tdi_lock);

        return Status;
    }

    ExReleaseResourceLite(&tdi_lock);

    ExAcquireResourceExclusiveLite(&tdi_lock, true);

    if (!net_conn.init && !no_reconnect) {
        OBJECT_ATTRIBUTES oa;

        KeSetEvent(&shutdown_event, 0, false);

        if (send_thread_handle)
            KeWaitForSingleObject(&send_thread_quit_event, Executive, KernelMode, false, nullptr);

        if (reap_thread_handle)
            KeWaitForSingleObject(&reap_thread_quit_event, Executive, KernelMode, false, nullptr);

        new (&net_conn) tdi(ip_address, PORT);

        if (!NT_SUCCESS(net_conn.Status)) {
            Status = net_conn.Status;

            ERR("tdi::tdi returned %08x\n", Status);
            net_conn.tdi::~tdi();
            ExReleaseResourceLite(&tdi_lock);

            return Status;
        }

        TRACE("TDI object opened.\n");

        KeResetEvent(&shutdown_event);

        InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

        Status = PsCreateSystemThread(&recv_thread_handle, 0, &oa, nullptr, nullptr, [](void* ctx) {
            ((smb_connexion*)ctx)->recv_thread();
        }, this);

        if (!NT_SUCCESS(Status)) {
            ERR("PsCreateSystemThread returned %08x\n", Status);
            net_conn.tdi::~tdi();
            ExReleaseResourceLite(&tdi_lock);

            return Status;
        }

        Status = send_smb1_negotiate_req();
        if (!NT_SUCCESS(Status)) {
            ERR("send_smb1_negotiate_req returned %08x\n", Status);
            ExReleaseResourceLite(&tdi_lock);
            return Status;
        }

        next_msg_id = 0;

        Status = PsCreateSystemThread(&send_thread_handle, 0, &oa, nullptr, nullptr, [](void* ctx) {
            ((smb_connexion*)ctx)->send_thread();
        }, this);
        if (!NT_SUCCESS(Status)) {
            ERR("PsCreateSystemThread returned %08x\n", Status);
            net_conn.tdi::~tdi();
            ExReleaseResourceLite(&tdi_lock);

            return Status;
        }

        Status = PsCreateSystemThread(&reap_thread_handle, 0, &oa, nullptr, nullptr, [](void* ctx) {
            ((smb_connexion*)ctx)->reap_thread();
        }, this);
        if (!NT_SUCCESS(Status)) {
            ERR("PsCreateSystemThread returned %08x\n", Status);
            net_conn.tdi::~tdi();
            ExReleaseResourceLite(&tdi_lock);

            return Status;
        }
    }

    Status = add_send_msg_to_queue(data, data_len, mw);

    ExReleaseResourceLite(&tdi_lock);

    return Status;
}

static void __stdcall irp_cancelled(PDEVICE_OBJECT, PIRP Irp) {
    IoReleaseCancelSpinLock(Irp->CancelIrql);

    // loop through msg_waits and set event

    ExAcquireResourceSharedLite(&connexion_lock, true);

    LIST_ENTRY* le = connexion_list.Flink;

    while (le != &connexion_list) {
        KIRQL irql;
        auto conn = CONTAINING_RECORD(le, smb_connexion, list_entry);

        KeAcquireSpinLock(&conn->msg_waits_spinlock, &irql);

        LIST_ENTRY* le2 = conn->msg_waits.Flink;
        while (le2 != &conn->msg_waits) {
            auto mw = CONTAINING_RECORD(le2, msg_wait, list_entry);

            if (mw->Irp == Irp) {
                KeSetEvent(&mw->event, 0, false);

                KeReleaseSpinLock(&conn->msg_waits_spinlock, irql);
                ExReleaseResourceLite(&connexion_lock);
                return;
            }

            le2 = le2->Flink;
        }

        KeReleaseSpinLock(&conn->msg_waits_spinlock, irql);

        le = le->Flink;
    }

    ExReleaseResourceLite(&connexion_lock);
}

NTSTATUS smb_connexion::wait_for_response(msg_wait* mw, char** resp, size_t* resp_len, PIRP Irp, bool return_pending, bool no_timeout) {
    NTSTATUS Status;
    KIRQL irql;
    LARGE_INTEGER timeout;
    bool pending = false, set_cancel_routine = false;
    PDRIVER_CANCEL old_cancel_routine = nullptr;

    timeout.QuadPart = -30000000; // 3 seconds

    if (Irp && no_timeout) {
        KIRQL irql;

        mw->Irp = Irp;

        IoAcquireCancelSpinLock(&irql);
        old_cancel_routine = IoSetCancelRoutine(Irp, irp_cancelled);
        IoReleaseCancelSpinLock(irql);

        set_cancel_routine = true;
    }

    do {
        Status = KeWaitForSingleObject(&mw->event, Executive, KernelMode, false, (pending && Irp) || no_timeout ? nullptr : &timeout);

        KeAcquireSpinLock(&msg_waits_spinlock, &irql);

        if (Status == STATUS_SUCCESS && mw->resp && mw->resp_len > 0 && reinterpret_cast<smb2_header*>(mw->resp)->Status == STATUS_PENDING) {
            // async response - keep msg_wait in list for now

            if (!return_pending)
                ExFreePool(mw->resp);
            else {
                *resp = mw->resp;
                *resp_len = mw->resp_len;
            }

            mw->resp = nullptr;

            pending = true;
            KeClearEvent(&mw->event);

            if (return_pending) {
                KeReleaseSpinLock(&msg_waits_spinlock, irql);
                break;
            }

            if (!set_cancel_routine && Irp) {
                KIRQL irql;

                mw->Irp = Irp;

                IoAcquireCancelSpinLock(&irql);
                old_cancel_routine = IoSetCancelRoutine(Irp, irp_cancelled);
                IoReleaseCancelSpinLock(irql);

                set_cancel_routine = true;
            }
        } else {
            RemoveEntryList(&mw->list_entry);
            pending = false;
        }

        KeReleaseSpinLock(&msg_waits_spinlock, irql);
    } while (pending);

    if (set_cancel_routine) {
        IoAcquireCancelSpinLock(&irql);
        IoSetCancelRoutine(Irp, nullptr);
        IoReleaseCancelSpinLock(irql);

        if (Irp->Cancel) {
            if (old_cancel_routine) {
                IoAcquireCancelSpinLock(&irql);
                old_cancel_routine(master_devobj, Irp);
                // cancel routine will release spin lock
            }

            if (mw->resp) {
                ExFreePool(mw->resp);
                mw->resp = nullptr;
            }

            // FIXME - send cancellation message to server

            return STATUS_CANCELLED;
        }
    }

    if (mw->resp_len == 0)
        return STATUS_CONNECTION_DISCONNECTED;

    if (Status == STATUS_SUCCESS && (!pending || !return_pending)) {
        *resp = mw->resp;
        *resp_len = mw->resp_len;
    }

    return Status;
}

NTSTATUS smb_connexion::send_smb1_negotiate_req() {
    NTSTATUS Status;
    size_t data_len = sizeof(smb1_negotiate_request);
    char* respbuf;
    size_t resp_len;
    msg_wait mw;
    KIRQL irql;

    unsigned int i = 0;
    while (protocols[i]) {
        data_len += 1 + strlen(protocols[i]) + 1;
        i++;
    }

    auto msg = (smb1_negotiate_request*)ExAllocatePoolWithTag(PagedPool, data_len, ALLOC_TAG);
    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    msg->header.StreamProtocolLength = _byteswap_ulong(data_len - sizeof(uint32_t));
    msg->header.Protocol = SMB_MAGIC;
    msg->header.Command = SMBnegprot;
    msg->header.Status = STATUS_SUCCESS;
    msg->header.Flags = FLAG_CASELESS_PATHNAMES | FLAG_CANONICAL_PATHNAMES;
    msg->header.Flags2 = FLAGS2_LONG_PATH_COMPONENTS | FLAGS2_EXTENDED_ATTRIBUTES | FLAGS2_IS_LONG_NAME |
                         FLAGS2_EXTENDED_SECURITY | FLAGS2_32_BIT_ERROR_CODES | FLAGS2_UNICODE_STRINGS;
    msg->header.PIDHigh = 0;

    // FIXME - do in one go if 64-bit
    *(ULONG*)msg->header.SecurityFeatures = 0;
    *(ULONG*)&msg->header.SecurityFeatures[4] = 0;

    msg->header.Reserved = 0;
    msg->header.TID = 0xffff;
    msg->header.PIDLow = 0xfeff;
    msg->header.UID = 0;
    msg->header.MID = 0;

    msg->WordCount = 0;
    msg->ByteCount = data_len - sizeof(smb1_negotiate_request);

    auto p = (uint8_t*)msg + sizeof(smb1_negotiate_request);

    i = 0;
    while (protocols[i]) {
        *p = 2; // meaning "dialect"
        p++;

        RtlCopyMemory(p, protocols[i], strlen(protocols[i]) + 1);
        p += strlen(protocols[i]) + 1;

        i++;
    }

    mw.msg_id = 0;
    KeInitializeEvent(&mw.event, NotificationEvent, false);

    KeAcquireSpinLock(&msg_waits_spinlock, &irql);
    InsertTailList(&msg_waits, &mw.list_entry);
    KeReleaseSpinLock(&msg_waits_spinlock, irql);

    ExAcquireResourceSharedLite(&tdi_lock, true);

    Status = net_conn.send(msg, data_len);
    if (!NT_SUCCESS(Status)) {
        ERR("tdi::send returned %08x\n", Status);
        ExReleaseResourceLite(&tdi_lock);

        KeAcquireSpinLock(&msg_waits_spinlock, &irql);
        RemoveEntryList(&mw.list_entry);
        KeReleaseSpinLock(&msg_waits_spinlock, irql);

        ExFreePool(msg);
        return Status;
    }

    ExReleaseResourceLite(&tdi_lock);

    Status = wait_for_response(&mw, &respbuf, &resp_len, nullptr);

    ExFreePool(msg);

    if (Status == STATUS_TIMEOUT) {
        ERR("timeout waiting for response\n");
        return Status;
    } else if (!NT_SUCCESS(Status)) {
        ERR("wait_for_response returned %08x\n", Status);
        return Status;
    }

    // FIXME - handle "SMB 2.???" dialect negotiation

    Status = reinterpret_cast<smb2_header*>(respbuf)->Status;

    if (!NT_SUCCESS(Status)) {
        ERR("server returned %08x in reply to negotiate message\n", Status);
        ExFreePool(respbuf);
        return Status;
    }

    if (resp_len < sizeof(smb2_negotiate_response) - sizeof(uint32_t)) {
        ERR("response was %u bytes, expected at least %u\n", resp_len, sizeof(smb2_negotiate_response) - sizeof(uint32_t));
        ExFreePool(respbuf);
        return STATUS_INVALID_PARAMETER;
    }

    TRACE("received successful reply to negotiate message\n");

    auto resp = reinterpret_cast<smb2_negotiate_response*>(respbuf);

    if (resp->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED) {
        ERR("cannot connect - server requires messages to be signed, which is not yet supported\n");
        ExFreePool(respbuf);
        return STATUS_NOT_SUPPORTED;
    }

    dialect = resp->DialectRevision; // FIXME - make sure this is acceptable

    TRACE("dialect %x\n", dialect);

    max_read = resp->MaxReadSize;
    max_write = resp->MaxWriteSize;

    // FIXME - do we need to save any more bits of the response?

    ExFreePool(respbuf);

    return Status;
}

void smb_connexion::setup_smb2_header(smb2_header* smb2h, uint32_t msg_len, uint64_t session_id, uint32_t tree_id) {
    RtlZeroMemory(smb2h, sizeof(smb2_header));

    smb2h->Protocol = SMB2_MAGIC;
    smb2h->StreamProtocolLength = _byteswap_ulong(msg_len - sizeof(uint32_t));

    smb2h->HeaderSize = sizeof(smb2_header) - sizeof(uint32_t);
    smb2h->TreeId = tree_id;
    smb2h->SessionId = session_id;
}

NTSTATUS smb_connexion::send_setup_session_request(PSecBuffer buf, uint64_t session_id, msg_wait* mw) {
    size_t msg_len = sizeof(smb2_session_setup_request) + buf->cbBuffer;
    NTSTATUS Status;

    auto msg = (smb2_session_setup_request*)ExAllocatePoolWithTag(PagedPool, msg_len, ALLOC_TAG);

    if (!msg) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    setup_smb2_header(msg, msg_len, session_id, 0);

    msg->Command = SMB2_OP_SESSSETUP;

    msg->StructureSize = (sizeof(smb2_session_setup_request) - sizeof(smb2_header)) | 1;
    msg->Flags = 0; // FIXME - support reconnexion
    msg->SecurityMode = 0; // FIXME - support signing
    msg->Capabilities = 0;
    msg->Channel = 0;
    msg->SecurityBufferOffset = buf->cbBuffer > 0 ? (sizeof(smb2_session_setup_request) - sizeof(uint32_t)) : 0;
    msg->SecurityBufferLength = (uint16_t)buf->cbBuffer;
    msg->PreviousSessionId = 0;

    if (buf->cbBuffer > 0)
        RtlCopyMemory((uint8_t*)msg + msg->SecurityBufferOffset + sizeof(uint32_t), buf->pvBuffer, buf->cbBuffer);

    Status = send(msg, msg_len, mw);
    if (!NT_SUCCESS(Status)) {
        ERR("smb_connexion::send returned %08x\n", Status);
        ExFreePool(msg);
        return Status;
    }

    ExFreePool(msg);

    return Status;
}

NTSTATUS smb_connexion::add_session(PSID sid, smb_session** sess) {
    LIST_ENTRY* le;

    if (shutting_down)
        return STATUS_TOO_LATE;

    ExAcquireResourceSharedLite(&session_lock, true);

    le = sessions.Flink;

    while (le != &sessions) {
        auto s = CONTAINING_RECORD(le, smb_session, list_entry);

        if (!s->dead && RtlEqualSid(sid, s->sid)) {
            InterlockedIncrement(&s->refcount);
            *sess = s;
            ExReleaseResourceLite(&session_lock);

            return STATUS_SUCCESS;
        }

        le = le->Flink;
    }

    ExReleaseResourceLite(&session_lock);

    ExAcquireResourceExclusiveLite(&session_lock, true);

    // check again

    le = sessions.Flink;

    while (le != &sessions) {
        auto s = CONTAINING_RECORD(le, smb_session, list_entry);

        if (!s->dead && RtlEqualSid(sid, s->sid)) {
            InterlockedIncrement(&s->refcount);
            *sess = s;
            ExReleaseResourceLite(&session_lock);

            return STATUS_SUCCESS;
        }

        le = le->Flink;
    }

    // still not found, create new

    auto s = (smb_session*)ExAllocatePoolWithTag(NonPagedPool, sizeof(smb_session), ALLOC_TAG);
    if (!s) {
        ERR("out of memory\n");
        ExReleaseResourceLite(&session_lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    new (s) smb_session(this, sid);

    if (!NT_SUCCESS(s->Status)) {
        Status = s->Status;

        ExReleaseResourceLite(&session_lock);

        ERR("smb_session::smb_session returned %08x\n", Status);

        s->smb_session::~smb_session();
        ExFreePool(s);
        return Status;
    }

    InsertTailList(&sessions, &s->list_entry);

    ExReleaseResourceLite(&session_lock);

    *sess = s;

    return STATUS_SUCCESS;
}

NTSTATUS smb_connexion::create_file(PIRP Irp, PUNICODE_STRING filename) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PSID sid = nullptr;
    smb_session* sess;

    TRACE("(%p, %.*S)\n", Irp, filename->Length / sizeof(WCHAR), filename->Buffer);

    // get SID

    if (IrpSp->Parameters.Create.SecurityContext && IrpSp->Parameters.Create.SecurityContext->AccessState) {
        PACCESS_TOKEN access_token;
        TOKEN_USER* tu;

        SeLockSubjectContext(&IrpSp->Parameters.Create.SecurityContext->AccessState->SubjectSecurityContext);

        access_token = SeQuerySubjectContextToken(&IrpSp->Parameters.Create.SecurityContext->AccessState->SubjectSecurityContext);

        Status = SeQueryInformationToken(access_token, TokenUser, (void**)&tu);

        SeUnlockSubjectContext(&IrpSp->Parameters.Create.SecurityContext->AccessState->SubjectSecurityContext);

        if (!NT_SUCCESS(Status)) {
            ERR("SeQueryInformationToken returned %08x\n", Status);
            return Status;
        } else {
            if (tu->User.Sid && RtlValidSid(tu->User.Sid)) {
                ULONG sid_length = RtlLengthSid(tu->User.Sid);

                sid = ExAllocatePoolWithTag(NonPagedPool, sid_length, ALLOC_TAG);
                if (!sid) {
                    ERR("out of memory\n");
                    ExFreePool(tu);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                RtlCopyMemory(sid, tu->User.Sid, sid_length);
            }

            ExFreePool(tu);
        }
    }

    if (!sid) {
        ERR("unable to get SID\n");
        return STATUS_INVALID_PARAMETER;
    }

    Status = add_session(sid, &sess);
    if (!NT_SUCCESS(Status)) {
        ERR("add_session returned %08x\n", Status);
        ExFreePool(sid);
        return Status;
    }

    ExFreePool(sid);

    Status = sess->create_file(Irp, filename);
    if (!NT_SUCCESS(Status))
        ERR("smb_session::create_file returned %08x\n", Status);

    InterlockedDecrement(&sess->refcount);

    return Status;
}

void smb_connexion::purge_cache() {
    LIST_ENTRY* le;

    ExAcquireResourceSharedLite(&session_lock, true);

    le = sessions.Flink;
    while (le != &sessions) {
        auto sess = CONTAINING_RECORD(le, smb_session, list_entry);

        sess->purge_cache();

        le = le->Flink;
    }

    ExReleaseResourceLite(&session_lock);
}

void smb_connexion::update_last_activity(uint64_t t) {
    last_activity = t;
}
