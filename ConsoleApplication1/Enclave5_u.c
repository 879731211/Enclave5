#include "Enclave5_u.h"
#include <errno.h>

typedef struct ms_foo_t {
	char* ms_buf;
	size_t ms_len;
} ms_foo_t;

typedef struct ms_unseal_data_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_sealed_blob;
	size_t ms_data_size;
	char* ms_TA_prikey;
	size_t ms_len;
} ms_unseal_data_t;

typedef struct ms_TA_tracing_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_sealed_blob;
	size_t ms_data_size;
	char* ms_id1_c;
	size_t ms_idl_c_size;
	char* ms_Tracing_RID;
	size_t ms_Tracing_RID_size;
	char* ms_Tracing_T;
	size_t ms_Tracing_T_size;
} ms_TA_tracing_t;

typedef struct ms_uprint_t {
	const char* ms_str;
} ms_uprint_t;

typedef struct ms_TA_store_key_t {
	uint8_t* ms_buf;
	size_t ms_len;
} ms_TA_store_key_t;

typedef struct ms_TA_store_pubkey_t {
	char* ms_key;
	size_t ms_len;
} ms_TA_store_pubkey_t;

typedef struct ms_TA_tracing_log_t {
	char* ms_log;
	size_t ms_len;
} ms_TA_tracing_log_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_u_sgxssl_ftime64_t {
	void* ms_timeptr;
	uint32_t ms_timeb64Len;
} ms_u_sgxssl_ftime64_t;

static sgx_status_t SGX_CDECL Enclave5_uprint(void* pms)
{
	ms_uprint_t* ms = SGX_CAST(ms_uprint_t*, pms);
	uprint(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave5_TA_store_key(void* pms)
{
	ms_TA_store_key_t* ms = SGX_CAST(ms_TA_store_key_t*, pms);
	TA_store_key(ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave5_TA_store_pubkey(void* pms)
{
	ms_TA_store_pubkey_t* ms = SGX_CAST(ms_TA_store_pubkey_t*, pms);
	TA_store_pubkey(ms->ms_key, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave5_TA_tracing_log(void* pms)
{
	ms_TA_tracing_log_t* ms = SGX_CAST(ms_TA_tracing_log_t*, pms);
	TA_tracing_log(ms->ms_log, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave5_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave5_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave5_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave5_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave5_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave5_u_sgxssl_ftime64(void* pms)
{
	ms_u_sgxssl_ftime64_t* ms = SGX_CAST(ms_u_sgxssl_ftime64_t*, pms);
	u_sgxssl_ftime64(ms->ms_timeptr, ms->ms_timeb64Len);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[10];
} ocall_table_Enclave5 = {
	10,
	{
		(void*)(uintptr_t)Enclave5_uprint,
		(void*)(uintptr_t)Enclave5_TA_store_key,
		(void*)(uintptr_t)Enclave5_TA_store_pubkey,
		(void*)(uintptr_t)Enclave5_TA_tracing_log,
		(void*)(uintptr_t)Enclave5_sgx_oc_cpuidex,
		(void*)(uintptr_t)Enclave5_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave5_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave5_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave5_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave5_u_sgxssl_ftime64,
	}
};

sgx_status_t foo(sgx_enclave_id_t eid, char* buf, size_t len)
{
	sgx_status_t status;
	ms_foo_t ms;
	ms.ms_buf = buf;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave5, &ms);
	return status;
}

sgx_status_t TA_gen_prikey(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave5, NULL);
	return status;
}

sgx_status_t unseal_data(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_blob, size_t data_size, char* TA_prikey, size_t len)
{
	sgx_status_t status;
	ms_unseal_data_t ms;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	ms.ms_TA_prikey = TA_prikey;
	ms.ms_len = len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave5, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t TA_tracing(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_blob, size_t data_size, char* id1_c, size_t idl_c_size, char* Tracing_RID, size_t Tracing_RID_size, char* Tracing_T, size_t Tracing_T_size)
{
	sgx_status_t status;
	ms_TA_tracing_t ms;
	ms.ms_sealed_blob = sealed_blob;
	ms.ms_data_size = data_size;
	ms.ms_id1_c = id1_c;
	ms.ms_idl_c_size = idl_c_size;
	ms.ms_Tracing_RID = Tracing_RID;
	ms.ms_Tracing_RID_size = Tracing_RID_size;
	ms.ms_Tracing_T = Tracing_T;
	ms.ms_Tracing_T_size = Tracing_T_size;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave5, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

