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
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <ntddser.h>

#ifdef _DEBUG

#ifdef _MSC_VER
#include <ntstrsafe.h>
#else
NTSTATUS RtlStringCbVPrintfA(char* pszDest, size_t cbDest, const char* pszFormat, va_list argList); // not in mingw
#endif

typedef struct {
    KEVENT Event;
    IO_STATUS_BLOCK iosb;
} logger_context;

serial_logger::serial_logger() {
    NTSTATUS Status;
    static const WCHAR log_device[] = L"\\Device\\Serial0";
    UNICODE_STRING us;
    SERIAL_BAUD_RATE sbr;
    KEVENT event;
    IO_STATUS_BLOCK iosb;
    PIRP Irp;

    ExInitializeResourceLite(&log_lock);

    us.Buffer = (WCHAR*)log_device;
    us.Length = us.MaximumLength = sizeof(log_device) - sizeof(WCHAR);

    Status = IoGetDeviceObjectPointer(&us, FILE_WRITE_DATA, &comfo, &comdo);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("IoGetDeviceObjectPointer returned %08x\n", Status);
        return;
    }

    KeInitializeEvent(&event, NotificationEvent, false);

    sbr.BaudRate = 115200;

    Irp = IoBuildDeviceIoControlRequest(IOCTL_SERIAL_SET_BAUD_RATE, comdo, &sbr, sizeof(sbr),
                                        nullptr, 0, false, &event, &iosb);
    if (!Irp) {
        DbgPrint("IoBuildDeviceIoControlRequest returned %08x\n", Status);
        return;
    }

    Status = IoCallDriver(comdo, Irp);

    if (Status == STATUS_PENDING)
        KeWaitForSingleObject(&event, Executive, KernelMode, false, NULL);
}

serial_logger::~serial_logger() {
    unloading = true;

    // sync
    ExAcquireResourceExclusiveLite(&log_lock, TRUE);
    ExReleaseResourceLite(&log_lock);

    if (comfo)
        ObDereferenceObject(comfo);

    ExDeleteResourceLite(&log_lock);
}

bool serial_logger::okay() {
    return comfo != nullptr;
}

static NTSTATUS __stdcall dbg_completion(PDEVICE_OBJECT, PIRP Irp, PVOID ctx) {
    auto context = (logger_context*)ctx;

    context->iosb = Irp->IoStatus;
    KeSetEvent(&context->Event, 0, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

void serial_logger::log(const char* func, const char* msg, ...) {
    NTSTATUS Status;
    PIRP Irp;
    PIO_STACK_LOCATION IrpSp;

    size_t buf_size = 1024;
    auto buf2 = (char*)ExAllocatePoolWithTag(NonPagedPool, buf_size, ALLOC_TAG);

    if (!buf2) {
        DbgPrint("Couldn't allocate buffer in debug_message\n");
        return;
    }

    _snprintf(buf2, buf_size, "%p:%s:", PsGetCurrentThread(), func);
    auto prefix_size = strlen(buf2);
    char* buf = &buf2[prefix_size];

    va_list ap;
    va_start(ap, msg);

    RtlStringCbVPrintfA(buf, buf_size - prefix_size, msg, ap);

    if (unloading) {
        DbgPrint(buf2);

        va_end(ap);

        ExFreePool(buf2);

        return;
    }

    ExAcquireResourceSharedLite(&log_lock, TRUE);

    auto length = (uint32_t)strlen(buf2);

    LARGE_INTEGER offset;
    offset.u.LowPart = 0;
    offset.u.HighPart = 0;

    logger_context* context = (logger_context*)ExAllocatePoolWithTag(NonPagedPool, sizeof(logger_context), ALLOC_TAG);
    if (!context) {
        DbgPrint("out of memory\n");
        goto exit2;
    }

    RtlZeroMemory(context, sizeof(logger_context));

    KeInitializeEvent(&context->Event, NotificationEvent, FALSE);

    Irp = IoAllocateIrp(comdo->StackSize, FALSE);

    if (!Irp) {
        DbgPrint("IoAllocateIrp failed\n");
        ExFreePool(context);
        goto exit2;
    }

    IrpSp = IoGetNextIrpStackLocation(Irp);
    IrpSp->MajorFunction = IRP_MJ_WRITE;

    if (comdo->Flags & DO_BUFFERED_IO) {
        Irp->AssociatedIrp.SystemBuffer = (void*)buf2;

        Irp->Flags = IRP_BUFFERED_IO;
    } else if (comdo->Flags & DO_DIRECT_IO) {
        Irp->MdlAddress = IoAllocateMdl((void*)buf2, length, FALSE, FALSE, NULL);
        if (!Irp->MdlAddress) {
            DbgPrint("IoAllocateMdl failed\n");
            goto exit;
        }

        MmBuildMdlForNonPagedPool(Irp->MdlAddress);
    } else
        Irp->UserBuffer = (void*)buf2;

    IrpSp->Parameters.Write.Length = length;
    IrpSp->Parameters.Write.ByteOffset = offset;

    Irp->UserIosb = &context->iosb;

    Irp->UserEvent = &context->Event;

    IoSetCompletionRoutine(Irp, dbg_completion, context, TRUE, TRUE, TRUE);

    Status = IoCallDriver(comdo, Irp);

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&context->Event, Executive, KernelMode, FALSE, NULL);
        Status = context->iosb.Status;
    }

    if (comdo->Flags & DO_DIRECT_IO)
        IoFreeMdl(Irp->MdlAddress);

    if (!NT_SUCCESS(Status)) {
        DbgPrint("failed to write to COM1 - error %08x\n", Status);
        goto exit;
    }

exit:
    IoFreeIrp(Irp);
    ExFreePool(context);

exit2:
    ExReleaseResourceLite(&log_lock);

    va_end(ap);

    if (buf2)
        ExFreePool(buf2);
}

void* serial_logger::operator new(size_t size) {
    return ExAllocatePoolWithTag(NonPagedPool, size, ALLOC_TAG);
}

void serial_logger::operator delete(void* p) {
    ExFreePool(p);
}

#endif
