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

#pragma once

#include <ntifs.h>
#include <tdi.h>
#include <stdint.h>
#include <new.h>
#include "smb.h"

#define ALLOC_TAG 0x66424D53 // 'SMBf'

static const uint16_t PORT = 445;

#ifdef _MSC_VER
#define funcname __FUNCTION__
#else
#define funcname __func__
#endif

#ifdef _DEBUG

extern unsigned int debug_log_level;

#define ERR(s, ...) do { if (logger) { logger->log(funcname, s, ##__VA_ARGS__); } } while (0);
#define FIXME(s, ...) do { if (logger) { logger->log(funcname, s, ##__VA_ARGS__); } } while (0);
#define WARN(s, ...) do { if (logger && debug_log_level >= 2) { logger->log(funcname, s, ##__VA_ARGS__); } } while (0);
#define TRACE(s, ...) do { if (logger && debug_log_level >= 3) { logger->log(funcname, s, ##__VA_ARGS__); } } while (0);

#else

#define ERR(s, ...) do { } while(0);
#define FIXME(s, ...) do { } while(0);
#define WARN(s, ...) do { } while(0);
#define TRACE(s, ...) do { } while(0);

#endif

#define WH2N(w) ((((w) & 0xFF00) >> 8) | (((w) & 0x00FF) << 8))

#ifdef __GNUC__
#define InterlockedIncrement64(a) __sync_add_and_fetch(a, 1)
#endif

// SEH not in mingw(?)
#ifdef __GNUC__
#define _SEH2_TRY
#define _SEH2_EXCEPT(s)
#define _SEH2_END
#elif _MSC_VER
#define _SEH2_TRY _try
#define _SEH2_EXCEPT(s) _except(s)
#define _SEH2_END
#endif

// FIXME - sort mingw issues
#ifdef _MSC_VER
#define SECURITY_KERNEL
#include <sspi.h>
#else

typedef LONG SECURITY_STATUS;
typedef UNICODE_STRING SECURITY_STRING,*PSECURITY_STRING;

typedef struct _SecHandle {
    ULONG_PTR dwLower;
    ULONG_PTR dwUpper;
} SecHandle, *PSecHandle;

typedef struct _SecBuffer {
    unsigned __LONG32 cbBuffer;
    unsigned __LONG32 BufferType;
    void *pvBuffer;
} SecBuffer, *PSecBuffer;

typedef struct _SecBufferDesc {
    unsigned __LONG32 ulVersion;
    unsigned __LONG32 cBuffers;
    PSecBuffer pBuffers;
} SecBufferDesc,*PSecBufferDesc;

typedef SecHandle CredHandle;
typedef PSecHandle PCredHandle;
typedef SecHandle CtxtHandle;
typedef PSecHandle PCtxtHandle;

typedef void (WINAPI *SEC_GET_KEY_FN) (void* Arg, void* Principal, unsigned __LONG32 KeyVer,
                                       void** Key, SECURITY_STATUS* Status);

typedef unsigned __LONG32 TimeStamp;
typedef unsigned __LONG32* PTimeStamp;

SECURITY_STATUS __stdcall
AcquireCredentialsHandleW(PSECURITY_STRING pPrincipal, PSECURITY_STRING pPackage, unsigned long fCredentialUse,
                          void* pvLogonId, void* pAuthData, SEC_GET_KEY_FN pGetKeyFn, void* pvGetKeyArgument,
                          PCredHandle phCredential, PTimeStamp ptsExpiry);

SECURITY_STATUS __stdcall FreeCredentialsHandle(PCredHandle phCredential);

SECURITY_STATUS __stdcall
InitializeSecurityContextW(PCredHandle phCredential, PCtxtHandle phContext, PSECURITY_STRING pTargetName,
                           unsigned __LONG32 fContextReq, unsigned __LONG32 Reserved1,
                           unsigned __LONG32 TargetDataRep, PSecBufferDesc pInput, unsigned __LONG32 Reserved2,
                           PCtxtHandle phNewContext, PSecBufferDesc pOutput, unsigned __LONG32* pfContextAttr,
                           PTimeStamp ptsExpiry);

SECURITY_STATUS __stdcall DeleteSecurityContext(PCtxtHandle phContext);

SECURITY_STATUS __stdcall FreeContextBuffer(void *pvContextBuffer);

#define SECPKG_CRED_OUTBOUND 0x00000002

#define ISC_REQ_ALLOCATE_MEMORY 0x00000100

#define SECURITY_NATIVE_DREP 0x00000010

#define SECBUFFER_VERSION 0

#define SECBUFFER_TOKEN 2

#endif

#ifdef _DEBUG
class serial_logger {
public:
    serial_logger();
    ~serial_logger();

    void* operator new(size_t size);
    void operator delete(void* p);

    bool okay();
    void log(const char* func, const char* msg, ...);

private:
    PFILE_OBJECT comfo = nullptr;
    PDEVICE_OBJECT comdo = nullptr;
    ERESOURCE log_lock;
    bool unloading = false;
};

extern serial_logger* logger;
#endif

class tdi {
public:
    tdi() { }
    tdi(uint32_t ip_address, uint16_t port);
    ~tdi();
    NTSTATUS send(void* data, ULONG data_len);
    NTSTATUS recv(char* buf, ULONG buflen, PULONG retlen, PKEVENT event2);

    NTSTATUS Status;
    bool init = false;

private:
    void open_address_file();
    void open_connexion_file();
    void connect(uint32_t ip_address, uint16_t port);
    NTSTATUS disconnect();

    PFILE_OBJECT address_obj = nullptr;
    HANDLE address_handle = nullptr;
    PFILE_OBJECT conn_obj = nullptr;
    HANDLE conn_handle = nullptr;
    PDEVICE_OBJECT conn_devobj = nullptr;
};

struct smb2_header;
class smb_session;
class smb_tree;

struct msg_wait {
    uint64_t msg_id;
    KEVENT event;
    PIRP Irp;
    LIST_ENTRY list_entry;
    char* resp;
    size_t resp_len;
};

struct send_msg {
    LIST_ENTRY list_entry;
    ULONG length;
    char data[1];
};

class smb_connexion {
public:
    smb_connexion(PUNICODE_STRING hostname, uint32_t ip_address);
    ~smb_connexion();
    NTSTATUS add_session(PSID sid, smb_session** sess);
    NTSTATUS create_file(PIRP Irp, PUNICODE_STRING filename);
    void setup_smb2_header(smb2_header* smb2h, uint32_t msg_len, uint64_t session_id, uint32_t tree_id);
    NTSTATUS send(void* data, ULONG data_len, msg_wait* mw, bool no_reconnect = false);
    NTSTATUS wait_for_response(msg_wait* mw, char** resp, size_t* resp_len, PIRP Irp, bool return_pending = false, bool no_timeout = false);
    void purge_cache();
    void update_last_activity(uint64_t t);

    LONG refcount = 1;
    uint32_t ip_address;
    LIST_ENTRY list_entry;
    NTSTATUS Status;
    UNICODE_STRING hostname;
    int64_t next_msg_id = 0;
    uint32_t max_read;
    uint32_t max_write;
    uint16_t dialect;
    LIST_ENTRY msg_waits;
    KSPIN_LOCK msg_waits_spinlock;
    uint64_t last_activity;
    ERESOURCE session_lock;

    friend smb_session;
    friend smb_tree;

private:
    void recv_thread();
    void send_thread();
    void reap_thread();
    NTSTATUS send_smb1_negotiate_req();
    void received_message(char* data, ULONG data_len);
    NTSTATUS send_setup_session_request(PSecBuffer buf, uint64_t session_id, msg_wait* mw);
    NTSTATUS add_send_msg_to_queue(void* data, ULONG data_len, msg_wait* mw);

    tdi net_conn;
    char buf[PAGE_SIZE];
    HANDLE recv_thread_handle = nullptr;
    HANDLE send_thread_handle = nullptr;
    HANDLE reap_thread_handle = nullptr;
    KEVENT shutdown_event;
    KEVENT recv_thread_quit_event;
    KEVENT send_thread_quit_event;
    KEVENT reap_thread_quit_event;
    ERESOURCE tdi_lock;
    char* partial_msgs = nullptr;
    ULONG partial_msgs_len = 0;
    LIST_ENTRY sessions;
    bool shutting_down = false;
    KSPIN_LOCK send_msg_spinlock;
    LIST_ENTRY send_msgs;
    KEVENT send_msg_event;
};

class smb_object;

class smb_tree {
public:
    smb_tree(smb_session* sess, PUNICODE_STRING name);
    ~smb_tree();
    NTSTATUS create_file(PIRP Irp, PUNICODE_STRING filename);
    NTSTATUS close_file(smb_object* obj, PFILE_OBJECT FileObject);
    void purge_cache();
    void update_last_activity();
    bool try_to_reap(uint64_t time);

    LONG refcount = 1;
    uint32_t tree_id;
    LIST_ENTRY list_entry;
    NTSTATUS Status;
    UNICODE_STRING name;
    bool shutting_down = false;
    LIST_ENTRY files;
    ERESOURCE file_lock;
    smb_session* sess;
    ERESOURCE name_lock;
    uint64_t last_activity;

private:
    NTSTATUS send_tree_connect_msg(PUNICODE_STRING name, msg_wait* mw);
    NTSTATUS tree_connect();
    NTSTATUS send_create_file_msg(PUNICODE_STRING name, uint32_t desired_access, uint32_t file_attributes,
                                  uint32_t share_access, uint32_t create_disposition, uint32_t create_options,
                                  msg_wait* mw);
    NTSTATUS send_tree_disconnect_msg(msg_wait* mw);

    uint8_t share_type;
    uint32_t share_flags;
    uint32_t capabilities;
    uint32_t maximal_access;
};

class smb_session {
public:
    smb_session(smb_connexion* conn, PSID sid);
    ~smb_session();
    NTSTATUS create_file(PIRP Irp, PUNICODE_STRING filename);
    NTSTATUS add_tree(PUNICODE_STRING name, smb_tree** tree);
    void purge_cache();
    void reap_trees();
    bool try_to_reap(uint64_t time);

    friend smb_tree;

    LONG refcount = 1;
    PSID sid = nullptr;
    LIST_ENTRY list_entry;
    NTSTATUS Status;
    ERESOURCE tree_lock;
    LIST_ENTRY trees;
    bool dead = false;
    bool shutting_down = false;
    smb_connexion* conn;
    uint64_t session_id;
    uint64_t last_activity;

private:
    NTSTATUS setup_session();
    void update_last_activity(uint64_t t = 0);
    NTSTATUS send_logoff_msg(msg_wait* mw);
};

struct smb_file_nonpaged {
    FAST_MUTEX header_mutex;
    ERESOURCE resource;
    ERESOURCE paging_resource;
    SECTION_OBJECT_POINTERS segment_object;
    LIST_ENTRY locks;
    KSPIN_LOCK locks_spinlock;
};

enum class smb_object_type {
    file,
    pipe
};

class smb_object {
public:
    smb_object(smb_tree* tree, PFILE_OBJECT FileObject);
    ~smb_object();

    virtual NTSTATUS directory_control(PIRP Irp);
    virtual NTSTATUS close(PFILE_OBJECT FileObject);
    virtual NTSTATUS read(PIRP Irp);
    virtual NTSTATUS write(PIRP Irp);
    virtual NTSTATUS query_information(PIRP Irp);
    virtual NTSTATUS set_information(PIRP Irp);
    virtual NTSTATUS query_volume_information(PIRP Irp);
    NTSTATUS filesystem_control(PIRP Irp);
    virtual NTSTATUS query_security(PIRP Irp);
    virtual NTSTATUS set_security(PIRP Irp);
    virtual NTSTATUS lock(PIRP Irp);
    virtual NTSTATUS flush(PIRP Irp);
    virtual void purge_cache();

    FSRTL_ADVANCED_FCB_HEADER header;
    smb_file_nonpaged* nonpaged;
    LIST_ENTRY list_entry;
    NTSTATUS Status;
    smb_tree* tree;
    smb_object_type type;
    SMB2_FILEID FileId;
    PFILE_OBJECT FileObject;

private:
    NTSTATUS send_ioctl_request_msg(void* input, ULONG input_len, uint32_t control_code,
                                    bool fsctl, uint32_t output_len, msg_wait* mw);
};

class smb_pipe : public smb_object {
public:
    smb_pipe(smb_tree* tree, PFILE_OBJECT FileObject) : smb_object(tree, FileObject) {
        type = smb_object_type::pipe;

        FileId.Persistent = 0xffffffffffffffff;
        FileId.Volatile = 0xffffffffffffffff;
    }

    ~smb_pipe() {
    }
};

struct smb_lock {
    LIST_ENTRY list_entry;
    uint64_t offset;
    uint64_t length;
    ULONG key;
};

class smb_file : public smb_object {
public:
    smb_file(smb_tree* tree, PFILE_OBJECT FileObject, PUNICODE_STRING filename, smb2_create_response* resp);
    ~smb_file();
    NTSTATUS directory_control(PIRP Irp) override;
    NTSTATUS close(PFILE_OBJECT FileObject) override;
    NTSTATUS read(PIRP Irp) override;
    NTSTATUS write(PIRP Irp) override;
    NTSTATUS query_information(PIRP Irp) override;
    NTSTATUS set_information(PIRP Irp) override;
    NTSTATUS query_volume_information(PIRP Irp) override;
    NTSTATUS query_security(PIRP Irp) override;
    NTSTATUS set_security(PIRP Irp) override;
    NTSTATUS lock(PIRP Irp) override;
    NTSTATUS flush(PIRP Irp) override;
    void purge_cache() override;

private:
    NTSTATUS query_directory(PIRP Irp);
    NTSTATUS notify_change_directory(PIRP Irp);
    NTSTATUS send_query_directory_msg(PUNICODE_STRING query_string, uint8_t file_information_class,
                                      uint32_t file_index, uint8_t flags, uint32_t length, msg_wait* mw);
    NTSTATUS send_query_info_msg(uint8_t info_type, uint8_t file_info_class, uint32_t length,
                                 uint32_t additional_info, msg_wait* mw);
    NTSTATUS send_read_msg(uint32_t length, uint64_t offset, msg_wait* mw);
    NTSTATUS send_write_msg(void* buf, uint32_t length, uint64_t offset, msg_wait* mw);
    NTSTATUS query_file_name_information(PIRP Irp);
    NTSTATUS query_file_remote_protocol_information(PIRP Irp);
    NTSTATUS send_set_info_msg(uint8_t info_type, uint8_t file_info_class, void* buf,
                               uint32_t length, uint32_t additional_info, msg_wait* mw);
    NTSTATUS set_rename_information(PIRP Irp);
    NTSTATUS send_change_notify_msg(bool watch_tree, uint32_t length, uint32_t completion_filter, msg_wait* mw);
    NTSTATUS send_lock_msg(uint16_t count, SMB2_LOCK_ELEMENT* elements, msg_wait* mw);
    NTSTATUS send_flush_msg(msg_wait* mw);

    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t FileAttributes;
    UNICODE_STRING query_string;
    UNICODE_STRING name;
};
