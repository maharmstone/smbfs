// This file is released into the public domain - do what you want
// with it.

#pragma once

// from Samba

// SMB 1
#define SMB_MAGIC     0x424D53FF /* 0xFF 'S' 'M' 'B' */

#define FLAG_SUPPORT_LOCKREAD       0x01
#define FLAG_CLIENT_BUF_AVAIL       0x02
#define FLAG_RESERVED               0x04
#define FLAG_CASELESS_PATHNAMES     0x08
#define FLAG_CANONICAL_PATHNAMES    0x10
#define FLAG_REQUEST_OPLOCK         0x20
#define FLAG_REQUEST_BATCH_OPLOCK   0x40
#define FLAG_REPLY                  0x80

#define FLAGS2_LONG_PATH_COMPONENTS             0x0001
#define FLAGS2_EXTENDED_ATTRIBUTES              0x0002
#define FLAGS2_SMB_SECURITY_SIGNATURES          0x0004
#define FLAGS2_COMPRESSED                       0x0008 /* MS-SMB */
#define FLAGS2_SMB_SECURITY_SIGNATURES_REQUIRED 0x0010
#define FLAGS2_IS_LONG_NAME                     0x0040
#define FLAGS2_REPARSE_PATH                     0x0400 /* MS-SMB @GMT- path. */
#define FLAGS2_EXTENDED_SECURITY                0x0800
#define FLAGS2_DFS_PATHNAMES                    0x1000
#define FLAGS2_READ_PERMIT_EXECUTE              0x2000
#define FLAGS2_32_BIT_ERROR_CODES               0x4000
#define FLAGS2_UNICODE_STRINGS                  0x8000

#define SMBnegprot    0x72   /* negotiate protocol */

// SMB 2

#define SMB2_MAGIC    0x424D53FE /* 0xFE 'S' 'M' 'B' */
#define SMB2_OP_NEGPROT     0x00
#define SMB2_OP_SESSSETUP   0x01
#define SMB2_OP_LOGOFF      0x02
#define SMB2_OP_TCON        0x03
#define SMB2_OP_TDIS        0x04
#define SMB2_OP_CREATE      0x05
#define SMB2_OP_CLOSE       0x06
#define SMB2_OP_FLUSH       0x07
#define SMB2_OP_READ        0x08
#define SMB2_OP_WRITE       0x09
#define SMB2_OP_LOCK        0x0a
#define SMB2_OP_IOCTL       0x0b
#define SMB2_OP_CANCEL      0x0c
#define SMB2_OP_KEEPALIVE   0x0d
#define SMB2_OP_QUERY_DIRECTORY 0x0e
#define SMB2_OP_NOTIFY      0x0f
#define SMB2_OP_GETINFO     0x10
#define SMB2_OP_SETINFO     0x11
#define SMB2_OP_BREAK       0x12

#define SMB2_HDR_FLAG_REDIRECT          0x01
#define SMB2_HDR_FLAG_ASYNC             0x02
#define SMB2_HDR_FLAG_CHAINED           0x04
#define SMB2_HDR_FLAG_SIGNED            0x08
#define SMB2_HDR_FLAG_PRIORITY_MASK     0x70
#define SMB2_HDR_FLAG_DFS               0x10000000
#define SMB2_HDR_FLAG_REPLAY_OPERATION  0x20000000

// from MSDN

#include <pshpack1.h>

struct smb_header {
    uint32_t StreamProtocolLength;
    uint32_t Protocol;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f
struct smb1_header : smb_header {
    uint8_t Command;
    NTSTATUS Status;
    uint8_t Flags;
    uint16_t Flags2;
    uint16_t PIDHigh;
    uint8_t SecurityFeatures[8];
    uint16_t Reserved;
    uint16_t TID;
    uint16_t PIDLow;
    uint16_t UID;
    uint16_t MID;
};

struct smb1_negotiate_request {
    smb1_header header;
    uint8_t WordCount;
    uint16_t ByteCount;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ea4560b7-90da-4803-82b5-344754b92a79
struct smb2_header : smb_header {
    uint16_t HeaderSize;
    uint16_t CreditCharge;
    NTSTATUS Status;
    uint16_t Command;
    uint16_t CreditRequest;
    uint32_t Flags;
    uint32_t NextCommand;
    uint64_t MessageId;

    union {
        struct {
            uint32_t Reserved;
            uint32_t TreeId;
        };
        uint64_t AsyncId;
    };

    uint64_t SessionId;
    uint8_t Signature[16];
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5
struct smb2_negotiate_response : smb2_header {
    uint16_t StructureSize;
    uint16_t SecurityMode;
    uint16_t DialectRevision;
    uint16_t NegotiateContextCount;
    uint8_t ServerGuid[16];
    uint32_t Capabilities;
    uint32_t MaxTransactSize;
    uint32_t MaxReadSize;
    uint32_t MaxWriteSize;
    uint64_t SystemTime;
    uint64_t ServerStartTime;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
    uint32_t NegotiateContextOffset;
};

#define SMB2_NEGOTIATE_SIGNING_ENABLED      0x0001
#define SMB2_NEGOTIATE_SIGNING_REQUIRED     0x0002

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a3c2c28-d6b0-48ed-b917-a86b2ca4575f
struct smb2_session_setup_request : smb2_header {
    uint16_t StructureSize;
    uint8_t Flags;
    uint8_t SecurityMode;
    uint32_t Capabilities;
    uint32_t Channel;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
    uint64_t PreviousSessionId;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0324190f-a31b-4666-9fa9-5c624273a694
struct smb2_session_setup_response : smb2_header {
    uint16_t StructureSize;
    uint16_t SessionFlags;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/832d2130-22e8-4afb-aafd-b30bb0901798
struct smb2_tree_connect_request : smb2_header {
    uint16_t StructureSize;
    uint16_t Flags;
    uint16_t PathOffset;
    uint16_t PathLength;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dd34e26c-a75e-47fa-aab2-6efc27502e96
struct smb2_tree_connect_response : smb2_header {
    uint16_t StructureSize;
    uint8_t ShareType;
    uint8_t Reserved;
    uint32_t ShareFlags;
    uint32_t Capabilities;
    uint32_t MaximalAccess;
};

#define SMB2_SHARE_TYPE_DISK  0x01
#define SMB2_SHARE_TYPE_PIPE  0x02
#define SMB2_SHARE_TYPE_PRINT 0x03

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997
struct smb2_create_request : smb2_header {
    uint16_t StructureSize;
    uint8_t SecurityFlags;
    uint8_t RequestedOplockLevel;
    uint32_t ImpersonationLevel;
    uint64_t SmbCreateFlags;
    uint64_t Reserved;
    uint32_t DesiredAccess;
    uint32_t FileAttributes;
    uint32_t ShareAccess;
    uint32_t CreateDisposition;
    uint32_t CreateOptions;
    uint16_t NameOffset;
    uint16_t NameLength;
    uint32_t CreateContextsOffset;
    uint32_t CreateContextsLength;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/f1d9b40d-e335-45fc-9d0b-199a31ede4c3
struct SMB2_FILEID {
    uint64_t Persistent;
    uint64_t Volatile;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d166aa9e-0b53-410e-b35e-3933d8131927
struct smb2_create_response : smb2_header {
    uint16_t StructureSize;
    uint8_t OplockLevel;
    uint8_t Flags;
    uint32_t CreateAction;
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t FileAttributes;
    uint32_t Reserved2;
    SMB2_FILEID FileId;
    uint32_t CreateContextsOffset;
    uint32_t CreateContextsLength;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/10906442-294c-46d3-8515-c277efe1f752
struct smb2_query_directory_request : smb2_header {
    uint16_t StructureSize;
    uint8_t FileInformationClass;
    uint8_t Flags;
    uint32_t FileIndex;
    SMB2_FILEID FileId;
    uint16_t FileNameOffset;
    uint16_t FileNameLength;
    uint32_t OutputBufferLength;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/4f75351b-048c-4a0c-9ea3-addd55a71956
struct smb2_query_directory_response : smb2_header {
    uint16_t StructureSize;
    uint16_t OutputBufferOffset;
    uint32_t OutputBufferLength;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/f84053b0-bcb2-4f85-9717-536dae2b02bd
struct smb2_close_request : smb2_header {
    uint16_t StructureSize;
    uint16_t Flags;
    uint32_t Reserved;
    SMB2_FILEID FileId;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d623b2f7-a5cd-4639-8cc9-71fa7d9f9ba9
struct smb2_query_info_request : smb2_header {
    uint16_t StructureSize;
    uint8_t InfoType;
    uint8_t FileInfoClass;
    uint32_t OutputBufferLength;
    uint16_t InputBufferOffset;
    uint16_t Reserved;
    uint32_t InputBufferLength;
    uint32_t AdditionalInformation;
    uint32_t Flags;
    SMB2_FILEID FileId;
};

#define SMB2_0_INFO_FILE        0x01
#define SMB2_0_INFO_FILESYSTEM  0x02
#define SMB2_0_INFO_SECURITY    0x03
#define SMB2_0_INFO_QUOTA       0x04

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3b1b3598-a898-44ca-bfac-2dcae065247f
struct smb2_query_info_response : smb2_header {
    uint16_t StructureSize;
    uint16_t OutputBufferOffset;
    uint32_t OutputBufferLength;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/320f04f3-1b28-45cd-aaa1-9e5aed810dca
struct smb2_read_request : smb2_header {
    uint16_t StructureSize;
    uint8_t Padding;
    uint8_t Flags;
    uint32_t Length;
    uint64_t Offset;
    SMB2_FILEID FileId;
    uint32_t MinimumCount;
    uint32_t Channel;
    uint32_t RemainingBytes;
    uint16_t ReadChannelInfoOffset;
    uint16_t ReadChannelInfoLength;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3e3d2f2c-0e2f-41ea-ad07-fbca6ffdfd90
struct smb2_read_response : smb2_header {
    uint16_t StructureSize;
    uint8_t DataOffset;
    uint8_t Reserved;
    uint32_t DataLength;
    uint32_t DataRemaining;
    uint32_t Reserved2;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e7046961-3318-4350-be2a-a8d69bb59ce8
struct smb2_write_request : smb2_header {
    uint16_t StructureSize;
    uint16_t DataOffset;
    uint32_t Length;
    uint64_t Offset;
    SMB2_FILEID FileId;
    uint32_t Channel;
    uint32_t RemainingBytes;
    uint16_t WriteChannelInfoOffset;
    uint16_t WriteChannelInfoLength;
    uint32_t Flags;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7b80a339-f4d3-4575-8ce2-70a06f24f133
struct smb2_write_response : smb2_header {
    uint16_t StructureSize;
    uint16_t Reserved;
    uint32_t Count;
    uint32_t Remaining;
    uint16_t WriteChannelInfoOffset;
    uint16_t WriteChannelInfoLength;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5c03c9d6-15de-48a2-9835-8fb37f8a79d8
struct smb2_ioctl_request : smb2_header {
    uint16_t StructureSize;
    uint16_t Reserved;
    uint32_t CtlCode;
    SMB2_FILEID FileId;
    uint32_t InputOffset;
    uint32_t InputCount;
    uint32_t MaxInputResponse;
    uint32_t OutputOffset;
    uint32_t OutputCount;
    uint32_t MaxOutputResponse;
    uint32_t Flags;
    uint32_t Reserved2;
};

#define SMB2_0_IOCTL_IS_FSCTL 0x1

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/f70eccb6-e1be-4db8-9c47-9ac86ef18dbb

struct smb2_ioctl_response : smb2_header {
    uint16_t StructureSize;
    uint16_t Reserved;
    uint32_t CtlCode;
    SMB2_FILEID FileId;
    uint32_t InputOffset;
    uint32_t InputCount;
    uint32_t OutputOffset;
    uint32_t OutputCount;
    uint32_t Flags;
    uint32_t Reserved2;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee9614c4-be54-4a3c-98f1-769a7032a0e4

struct smb2_set_info_request : smb2_header {
    uint16_t StructureSize;
    uint8_t InfoType;
    uint8_t FileInfoClass;
    uint32_t BufferLength;
    uint16_t BufferOffset;
    uint16_t Reserved;
    uint32_t AdditionalInformation;
    SMB2_FILEID FileId;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c4318eb4-bdab-49b7-9352-abd7005c7f19

struct smb2_set_info_response : smb2_header {
    uint16_t StructureSize;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/52aa0b70-8094-4971-862d-79793f41e6a8

struct FILE_RENAME_INFORMATION_TYPE_2 {
    uint8_t ReplaceIfExists;
    uint8_t Reserved[7];
    uint64_t RootDirectory;
    uint32_t FileNameLength;
    WCHAR FileName[1];
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/598f395a-e7a2-4cc8-afb3-ccb30dd2df7c

struct smb2_change_notify_request : smb2_header {
    uint16_t StructureSize;
    uint16_t Flags;
    uint32_t OutputBufferLength;
    SMB2_FILEID FileId;
    uint32_t CompletionFilter;
    uint32_t Reserved;
};

#define SMB2_WATCH_TREE 0x1

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/14f9d050-27b2-49df-b009-54e08e8bf7b5

struct smb2_change_notify_response : smb2_header {
    uint16_t StructureSize;
    uint16_t OutputBufferOffset;
    uint32_t OutputBufferLength;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6178b960-48b6-4999-b589-669f88e9017d

struct smb2_lock_request : smb2_header {
    uint16_t StructureSize;
    uint16_t LockCount;
    uint32_t LockSequenceNumber : 4;
    uint32_t LockSequenceIndex : 28;
    SMB2_FILEID FileId;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/73e941c7-9b07-42f6-8b0f-31c1a2cbf0b2

struct SMB2_LOCK_ELEMENT {
    uint64_t Offset;
    uint64_t Length;
    uint32_t Flags;
    uint32_t Reserved;
};

#define SMB2_LOCKFLAG_SHARED_LOCK       0x00000001
#define SMB2_LOCKFLAG_EXCLUSIVE_LOCK    0x00000002
#define SMB2_LOCKFLAG_UNLOCK            0x00000004
#define SMB2_LOCKFLAG_FAIL_IMMEDIATELY  0x00000010

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e494678b-b1fc-44a0-b86e-8195acf74ad7

struct smb2_flush_request : smb2_header {
    uint16_t StructureSize;
    uint16_t Reserved1;
    uint32_t Reserved2;
    SMB2_FILEID FileId;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/8a622ecb-ffee-41b9-b4c4-83ff2d3aba1b

struct smb2_tree_disconnect_request : smb2_header {
    uint16_t StructureSize;
    uint16_t Reserved;
};

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/abdc4ea9-52df-480e-9a36-34f104797d2c

struct smb2_logoff_request : smb2_header {
    uint16_t StructureSize;
    uint16_t Reserved;
};

#include <poppack.h>
