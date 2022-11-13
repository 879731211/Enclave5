#include "Enclave5_t.h"

#include "sgx_trts.h"
#include "sgx_tseal.h"

#include <string.h>
#include "windows.h"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include<string.h>
#include<sstream>
#include <stdlib.h>
#include <stdarg.h>

char* hexbin(char* hex) {

	char* bin = new char[40];
	char a0[] = "0000";
	char a1[] = "0001";
	char a2[] = "0010";
	char a3[] = "0011";
	char a4[] = "0100";
	char a5[] = "0101";
	char a6[] = "0110";
	char a7[] = "0111";
	char a8[] = "1000";
	char a9[] = "1001";
	char a10[] = "1010";
	char a11[] = "1011";
	char a12[] = "1100";
	char a13[] = "1101";
	char a14[] = "1110";
	char a15[] = "1111";
	for (int i = 0; i < 10; i++) {

		switch (hex[i])
		{
		case '0': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a0[j]; break;
		case '1': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a1[j]; break;
		case '2': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a2[j]; break;
		case '3': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a3[j]; break;
		case '4': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a4[j]; break;
		case '5': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a5[j]; break;
		case '6': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a6[j]; break;
		case '7': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a7[j]; break;
		case '8': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a8[j]; break;
		case '9': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a9[j]; break;
		case 'A': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a10[j]; break;
		case 'B': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a11[j]; break;
		case 'C': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a12[j]; break;
		case 'D': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a13[j]; break;
		case 'E': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a14[j]; break;
		case 'F': for (int j = 0; j <  4; j++)bin[i * 4 + j] = a15[j]; break;
		}
	}

	return bin;

}

double power(double x, int n) {  // 返回给定数字的乘幂，返回类型为double型
	double val = 1.0;

	while (n--) {
		val *= x;
	}
	return val;
}

void foo(char* buf, size_t len)
{
	BIGNUM* ri;
	ri = BN_new();
	const char* secret = "222222222222222";

	char s2[100];
	if (len > strlen(secret))
	{
		BN_dec2bn(&ri, secret);
		//char *res = BN_bn2dec(ri);
		memcpy(buf, BN_bn2dec(ri), strlen(secret) + 1);
		//OPENSSL_free(res);
	}
	
}
void printf(const char* fmt, ...)
{
	char buf[BUFSIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	uprint(buf);
}

void mystery1(char* s1, const char* s2)
{
	while (*s1 != '\0')
		s1++;

	for (; *s1 = *s2; s1++, s2++)
		; // empty statement
}


void TA_gen_prikey() {

	//TA初始化阶段
	int rc = 0;
	int nid = 0;
	EC_KEY* key = NULL;
	EC_GROUP* group = NULL;
	EC_builtin_curve* curves = NULL;
	int crv_len = 0;
	int key_size = 0;
	unsigned int sign_len = 0;
	BN_CTX* ctx = NULL;
	ctx = BN_CTX_new();

	BIGNUM* gx, * gy;
	gx = BN_new();
	gy = BN_new();
	/* 选择一种椭圆曲线 */
	nid = OBJ_sn2nid("SM2");

	/* 根据选择的椭圆曲线生成密钥参数 group */
	group = EC_GROUP_new_by_curve_name(nid);


	/* 构造EC_KEY数据结构 */
	key = EC_KEY_new();
	if (key == NULL) {
		printf("EC_KEY_new err.\n");
		return;
	}
	/* 设置密钥参数 */
	rc = EC_KEY_set_group(key, group);
	if (rc != 1) {
		printf("EC_KEY_set_group err.\n");
		return ;
	}
	/* 生成密钥 */
	
	rc = EC_KEY_generate_key(key);
	if (rc != 1) {
		printf("EC_KEY_generate_key err.\n");
		return ;
	}
	key_size = ECDSA_size(key);
	//printf("key_size = %d\n", key_size);
	const BIGNUM* pri_key = EC_KEY_get0_private_key(key);

	//printf("priv_key:%s \n", BN_bn2hex(pri_key));

	//printf("key_size = %d\n", strlen(BN_bn2hex(pri_key)));


	const EC_POINT* pub_key = NULL;
	pub_key = EC_KEY_get0_public_key(key);
	EC_POINT_get_affine_coordinates(group, pub_key, gx, gy, NULL);
	//printf("pub_key_x:%s \n", BN_bn2hex(gx));
	//printf("pub_key_y:%s \n", BN_bn2hex(gy));
	


	uint32_t sealed_data_size = sgx_calc_sealed_data_size(NULL, (uint32_t)strlen(BN_bn2hex(pri_key)));

	uint8_t* temp_sealed_buf = (uint8_t*)malloc(sealed_data_size);

	sgx_seal_data(NULL, NULL, (uint32_t)strlen(BN_bn2hex(pri_key)), (uint8_t*)BN_bn2hex(pri_key), sealed_data_size, (sgx_sealed_data_t*)temp_sealed_buf);
	
	//printf("key_size = %d\n", sealed_data_size);

	//printf("temp_sealed_buf = %d\n", temp_sealed_buf);
	
	TA_store_key(temp_sealed_buf, sealed_data_size);

	free(temp_sealed_buf);

	//printf("key_size = %d\n", ECDSA_size(key));

	
	//printf("pub-key = %s\n", EC_POINT_point2hex(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, ctx));
	TA_store_pubkey(EC_POINT_point2hex(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, ctx),strlen(EC_POINT_point2hex(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, ctx)));



	EC_GROUP_free(group), group = NULL;
	BN_CTX_free(ctx);
}


sgx_status_t unseal_data(const uint8_t* sealed_blob, size_t data_size, char* TA_prikey,size_t len) {

	uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t*)sealed_blob);
	uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t*)sealed_blob);
	if (mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX)
		return SGX_ERROR_UNEXPECTED;
	if (mac_text_len > data_size || decrypt_data_len > data_size)
		return SGX_ERROR_INVALID_PARAMETER;

	uint8_t* de_mac_text = (uint8_t*)malloc(mac_text_len);
	if (de_mac_text == NULL)
		return SGX_ERROR_OUT_OF_MEMORY;

	uint8_t* decrypt_data = (uint8_t*)malloc(decrypt_data_len);
	if (decrypt_data == NULL)
	{
		free(de_mac_text);
		return SGX_ERROR_OUT_OF_MEMORY;
	}
	sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t*)sealed_blob, de_mac_text, &mac_text_len, decrypt_data, &decrypt_data_len);
	if (ret != SGX_SUCCESS)
	{
		free(de_mac_text);
		free(decrypt_data);
		return ret;
	}

	printf("decrypt_data:%s \n", (char*)decrypt_data);

	printf("decrypt_data_size = %d\n", strlen((char*)decrypt_data));


	memcpy(TA_prikey, (char*)decrypt_data, 64);

	return ret;
}

sgx_status_t TA_tracing(const uint8_t* sealed_blob, size_t data_size, char* id1_c, size_t idl_c_size, char* Tracing_RID, size_t Tracing_RID_size,char* Tracing_T, size_t Tracing_T_size) {
	uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t*)sealed_blob);
	uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t*)sealed_blob);
	if (mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX)
		return SGX_ERROR_UNEXPECTED;
	if (mac_text_len > data_size || decrypt_data_len > data_size)
		return SGX_ERROR_INVALID_PARAMETER;

	uint8_t* de_mac_text = (uint8_t*)malloc(mac_text_len);
	if (de_mac_text == NULL)
		return SGX_ERROR_OUT_OF_MEMORY;

	uint8_t* decrypt_data = (uint8_t*)malloc(decrypt_data_len);
	if (decrypt_data == NULL)
	{
		free(de_mac_text);
		return SGX_ERROR_OUT_OF_MEMORY;
	}
	sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t*)sealed_blob, de_mac_text, &mac_text_len, decrypt_data, &decrypt_data_len);
	if (ret != SGX_SUCCESS)
	{
		free(de_mac_text);
		free(decrypt_data);
		return ret;
	}

	BN_CTX* ctx = NULL;
	ctx = BN_CTX_new();
	int nid = 0;
	/* 选择一种椭圆曲线 */
	nid = OBJ_sn2nid("SM2");
	EC_GROUP* group = NULL;
	/* 根据选择的椭圆曲线生成密钥参数 group */
	group = EC_GROUP_new_by_curve_name(nid);
	if (group == NULL) {
		printf("EC_GROUP_new_by_curve_name err!\n");
	}

	printf("decrypt_data:%s \n", (char*)decrypt_data);

	char TA_prikey[100]="";
	memcpy(TA_prikey, (char*)decrypt_data, 64);
	printf("TA_prikey:%s \n", TA_prikey);

	BIGNUM* pri_key;
	pri_key = BN_new();
	BN_hex2bn(&pri_key, TA_prikey);

	
	EC_POINT* ID1 = NULL;
	ID1 = EC_POINT_new(group);
	EC_POINT_hex2point(group, id1_c, ID1, ctx);

	//TA去匿名
	EC_POINT* s_ID1 = NULL;
	s_ID1 = EC_POINT_new(group);
	EC_POINT_mul(group, s_ID1, NULL, ID1, pri_key, ctx);

	const unsigned char* id_h = (const unsigned char*)(EC_POINT_point2hex(group, s_ID1, POINT_CONVERSION_COMPRESSED, ctx));
	unsigned char hash_idh[20] = { 0 };
	SHA1(id_h, strlen((char*)id_h), hash_idh);

	//hash字符数组转成大数
	BIGNUM* idh = BN_new();
	BN_bin2bn(hash_idh, 20, idh);

	char* idh_hex = BN_bn2hex(idh);


	printf("idh_hex_length: %d \n", Tracing_RID_size);
	

	char* idh_bin = hexbin(idh_hex);
	printf("idh_bin: %s \n", idh_bin);

	int* intbf = new int[strlen(idh_bin)];
	for (int i = 0; i < strlen(idh_bin); i++) {
		intbf[i] = idh_bin[i] - '0';
	}



	printf("Tracing_RID:%s \n", Tracing_RID);
	


	for (int k = 0; k < Tracing_RID_size; k++) {
		Tracing_RID[k] = Tracing_RID[k] ^ intbf[k];
	}

	printf("Tracing_RID:%s \n", Tracing_RID);

	double rid_int = 0;
	for (int i = 0; i < Tracing_RID_size; i++) {

		if (Tracing_RID[Tracing_RID_size - i - 1] == '1')rid_int += power(2, i);
		
	}

	printf("rid_int:%.0lf \n", rid_int);

	
	char rid[100];
	
	snprintf(rid, sizeof(rid), "%.0lf", rid_int);
	printf("int %s \n", rid);

	char* log = "TA start tracing ID:";

	//printf("Tracing_log:%s \n", log);
	mystery1(log, rid);
	//printf("Tracing_log:%s \n", log);
	mystery1(log, " ,in: ");
	//printf("Tracing_log:%s \n", log);
	mystery1(log, Tracing_T);
	//printf("Tracing_log:%s \n", log);

	TA_tracing_log(log, strlen(log));
	
	EC_POINT_free(ID1);
	BN_free(pri_key);
	EC_POINT_free(s_ID1);
	EC_POINT_free(ID1);

	EC_GROUP_free(group), group = NULL;
	BN_CTX_free(ctx);
	
	return ret;
}