#ifndef ENCLAVE5_U_H__
#define ENCLAVE5_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "openssl/ec.h"
#include "openssl/bn.h"
#include "openssl/ecdsa.h"
#include "stdio.h"
#include "openssl/ec.h"
#include "openssl/bn.h"
#include "openssl/ecdsa.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef UPRINT_DEFINED__
#define UPRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, uprint, (const char* str));
#endif
#ifndef TA_STORE_KEY_DEFINED__
#define TA_STORE_KEY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, TA_store_key, (uint8_t* buf, size_t len));
#endif
#ifndef TA_STORE_PUBKEY_DEFINED__
#define TA_STORE_PUBKEY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, TA_store_pubkey, (char* key, size_t len));
#endif
#ifndef TA_TRACING_LOG_DEFINED__
#define TA_TRACING_LOG_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, TA_tracing_log, (char* log, size_t len));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef U_SGXSSL_FTIME64_DEFINED__
#define U_SGXSSL_FTIME64_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime64, (void* timeptr, uint32_t timeb64Len));
#endif

sgx_status_t foo(sgx_enclave_id_t eid, char* buf, size_t len);
sgx_status_t TA_gen_prikey(sgx_enclave_id_t eid);
sgx_status_t unseal_data(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_blob, size_t data_size, char* TA_prikey, size_t len);
sgx_status_t TA_tracing(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_blob, size_t data_size, char* id1_c, size_t idl_c_size, char* Tracing_RID, size_t Tracing_RID_size, char* Tracing_T, size_t Tracing_T_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
