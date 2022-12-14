#ifndef ENCLAVE5_T_H__
#define ENCLAVE5_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "openssl/ec.h"
#include "openssl/bn.h"
#include "openssl/ecdsa.h"
#include "stdio.h"
#include "sgxssl_texception.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void foo(char* buf, size_t len);
void TA_gen_prikey(void);
sgx_status_t unseal_data(const uint8_t* sealed_blob, size_t data_size, char* TA_prikey, size_t len);
sgx_status_t TA_tracing(const uint8_t* sealed_blob, size_t data_size, char* id1_c, size_t idl_c_size, char* Tracing_RID, size_t Tracing_RID_size, char* Tracing_T, size_t Tracing_T_size);

sgx_status_t SGX_CDECL uprint(const char* str);
sgx_status_t SGX_CDECL TA_store_key(uint8_t* buf, size_t len);
sgx_status_t SGX_CDECL TA_store_pubkey(char* key, size_t len);
sgx_status_t SGX_CDECL TA_tracing_log(char* log, size_t len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL u_sgxssl_ftime64(void* timeptr, uint32_t timeb64Len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
