#include "Enclave5_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#pragma warning(disable: 4090)
#endif

static sgx_status_t SGX_CDECL sgx_foo(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_foo_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_foo_t* ms = SGX_CAST(ms_foo_t*, pms);
	ms_foo_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_foo_t), ms, sizeof(ms_foo_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = __in_ms.ms_buf;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_buf = _tmp_len;
	char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_buf = (char*)malloc(_len_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_buf, 0, _len_buf);
	}
	foo(_in_buf, _tmp_len);
	if (_in_buf) {
		if (memcpy_verw_s(_tmp_buf, _len_buf, _in_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_TA_gen_prikey(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	TA_gen_prikey();
	return status;
}

static sgx_status_t SGX_CDECL sgx_unseal_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_unseal_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_unseal_data_t* ms = SGX_CAST(ms_unseal_data_t*, pms);
	ms_unseal_data_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_unseal_data_t), ms, sizeof(ms_unseal_data_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_sealed_blob = __in_ms.ms_sealed_blob;
	size_t _tmp_data_size = __in_ms.ms_data_size;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;
	char* _tmp_TA_prikey = __in_ms.ms_TA_prikey;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_TA_prikey = _tmp_len;
	char* _in_TA_prikey = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);
	CHECK_UNIQUE_POINTER(_tmp_TA_prikey, _len_TA_prikey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob);
		if (_in_sealed_blob == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_blob, _len_sealed_blob, _tmp_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_TA_prikey != NULL && _len_TA_prikey != 0) {
		if ( _len_TA_prikey % sizeof(*_tmp_TA_prikey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_TA_prikey = (char*)malloc(_len_TA_prikey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_TA_prikey, 0, _len_TA_prikey);
	}
	_in_retval = unseal_data((const uint8_t*)_in_sealed_blob, _tmp_data_size, _in_TA_prikey, _tmp_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_TA_prikey) {
		if (memcpy_verw_s(_tmp_TA_prikey, _len_TA_prikey, _in_TA_prikey, _len_TA_prikey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_blob) free(_in_sealed_blob);
	if (_in_TA_prikey) free(_in_TA_prikey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_TA_tracing(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_TA_tracing_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_TA_tracing_t* ms = SGX_CAST(ms_TA_tracing_t*, pms);
	ms_TA_tracing_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_TA_tracing_t), ms, sizeof(ms_TA_tracing_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_sealed_blob = __in_ms.ms_sealed_blob;
	size_t _tmp_data_size = __in_ms.ms_data_size;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;
	char* _tmp_id1_c = __in_ms.ms_id1_c;
	size_t _tmp_idl_c_size = __in_ms.ms_idl_c_size;
	size_t _len_id1_c = _tmp_idl_c_size;
	char* _in_id1_c = NULL;
	char* _tmp_Tracing_RID = __in_ms.ms_Tracing_RID;
	size_t _tmp_Tracing_RID_size = __in_ms.ms_Tracing_RID_size;
	size_t _len_Tracing_RID = _tmp_Tracing_RID_size;
	char* _in_Tracing_RID = NULL;
	char* _tmp_Tracing_T = __in_ms.ms_Tracing_T;
	size_t _tmp_Tracing_T_size = __in_ms.ms_Tracing_T_size;
	size_t _len_Tracing_T = _tmp_Tracing_T_size;
	char* _in_Tracing_T = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);
	CHECK_UNIQUE_POINTER(_tmp_id1_c, _len_id1_c);
	CHECK_UNIQUE_POINTER(_tmp_Tracing_RID, _len_Tracing_RID);
	CHECK_UNIQUE_POINTER(_tmp_Tracing_T, _len_Tracing_T);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob);
		if (_in_sealed_blob == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_blob, _len_sealed_blob, _tmp_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_id1_c != NULL && _len_id1_c != 0) {
		if ( _len_id1_c % sizeof(*_tmp_id1_c) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_id1_c = (char*)malloc(_len_id1_c);
		if (_in_id1_c == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_id1_c, _len_id1_c, _tmp_id1_c, _len_id1_c)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_Tracing_RID != NULL && _len_Tracing_RID != 0) {
		if ( _len_Tracing_RID % sizeof(*_tmp_Tracing_RID) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_Tracing_RID = (char*)malloc(_len_Tracing_RID);
		if (_in_Tracing_RID == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_Tracing_RID, _len_Tracing_RID, _tmp_Tracing_RID, _len_Tracing_RID)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_Tracing_T != NULL && _len_Tracing_T != 0) {
		if ( _len_Tracing_T % sizeof(*_tmp_Tracing_T) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_Tracing_T = (char*)malloc(_len_Tracing_T);
		if (_in_Tracing_T == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_Tracing_T, _len_Tracing_T, _tmp_Tracing_T, _len_Tracing_T)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = TA_tracing((const uint8_t*)_in_sealed_blob, _tmp_data_size, _in_id1_c, _tmp_idl_c_size, _in_Tracing_RID, _tmp_Tracing_RID_size, _in_Tracing_T, _tmp_Tracing_T_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_sealed_blob) free(_in_sealed_blob);
	if (_in_id1_c) free(_in_id1_c);
	if (_in_Tracing_RID) free(_in_Tracing_RID);
	if (_in_Tracing_T) free(_in_Tracing_T);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_foo, 0, 0},
		{(void*)(uintptr_t)sgx_TA_gen_prikey, 0, 0},
		{(void*)(uintptr_t)sgx_unseal_data, 0, 0},
		{(void*)(uintptr_t)sgx_TA_tracing, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[10][4];
} g_dyn_entry_table = {
	10,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL uprint(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_uprint_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_uprint_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_uprint_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_uprint_t));
	ocalloc_size -= sizeof(ms_uprint_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL TA_store_key(uint8_t* buf, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_TA_store_key_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_TA_store_key_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_TA_store_key_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_TA_store_key_t));
	ocalloc_size -= sizeof(ms_TA_store_key_t);

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL TA_store_pubkey(char* key, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_key = len;

	ms_TA_store_pubkey_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_TA_store_pubkey_t);
	void *__tmp = NULL;

	void *__tmp_key = NULL;

	CHECK_ENCLAVE_POINTER(key, _len_key);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (key != NULL) ? _len_key : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_TA_store_pubkey_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_TA_store_pubkey_t));
	ocalloc_size -= sizeof(ms_TA_store_pubkey_t);

	if (key != NULL) {
		if (memcpy_verw_s(&ms->ms_key, sizeof(char*), &__tmp, sizeof(char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_key = __tmp;
		if (_len_key % sizeof(*key) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, key, _len_key)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_key);
		ocalloc_size -= _len_key;
	} else {
		ms->ms_key = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (key) {
			if (memcpy_s((void*)key, _len_key, __tmp_key, _len_key)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL TA_tracing_log(char* log, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_log = len;

	ms_TA_tracing_log_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_TA_tracing_log_t);
	void *__tmp = NULL;

	void *__tmp_log = NULL;

	CHECK_ENCLAVE_POINTER(log, _len_log);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (log != NULL) ? _len_log : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_TA_tracing_log_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_TA_tracing_log_t));
	ocalloc_size -= sizeof(ms_TA_tracing_log_t);

	if (log != NULL) {
		if (memcpy_verw_s(&ms->ms_log, sizeof(char*), &__tmp, sizeof(char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_log = __tmp;
		if (_len_log % sizeof(*log) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, log, _len_log)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_log);
		ocalloc_size -= _len_log;
	} else {
		ms->ms_log = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (log) {
			if (memcpy_s((void*)log, _len_log, __tmp_log, _len_log)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (memcpy_verw_s(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (memcpy_verw_s(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_ftime64(void* timeptr, uint32_t timeb64Len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb64Len;

	ms_u_sgxssl_ftime64_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime64_t);
	void *__tmp = NULL;

	void *__tmp_timeptr = NULL;

	CHECK_ENCLAVE_POINTER(timeptr, _len_timeptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeptr != NULL) ? _len_timeptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime64_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime64_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_ftime64_t);

	if (timeptr != NULL) {
		if (memcpy_verw_s(&ms->ms_timeptr, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_timeptr = __tmp;
		memset_verw(__tmp_timeptr, 0, _len_timeptr);
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		ocalloc_size -= _len_timeptr;
	} else {
		ms->ms_timeptr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_timeb64Len, sizeof(ms->ms_timeb64Len), &timeb64Len, sizeof(timeb64Len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (timeptr) {
			if (memcpy_s((void*)timeptr, _len_timeptr, __tmp_timeptr, _len_timeptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
