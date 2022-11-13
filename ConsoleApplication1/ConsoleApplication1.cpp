#pragma comment(lib, "ws2_32.lib")

#include <stdio.h>
#include <tchar.h>
#include "sgx_urts.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>

#include <openssl/err.h>
#include <openssl/sha.h>
#include "Enclave5_u.h"
#include <iostream>
#include <openssl/pem.h>
#include <fstream>

#include "tainitial.h"
#include"User_initial.h"
#include"User_Encounter.h"
#include"User_Verify.h"
#include"User_batch_ver.h"
#include"TA_Tracing.h"

#pragma warning(disable:4996）


#define ENCLAVE_FILE _T("../Debug/Enclave5.signed.dll")
#define MAX_BUF_LEN 100
using namespace std;

#ifdef __cplusplus
extern "C" {
#include <openssl/applink.c>
#endif

	void uprint(const char* str)
	{
		printf("%s", str);
	}
#ifdef __cplusplus
}
#endif

void TA_store_key(uint8_t* buf, size_t len) {

	std::ofstream ofs("C:\\Users\\87973\\source\\repos\\Enclave5\\initial_data\\TA_private.txt", std::ios::binary | std::ios::out);
	
	ofs.seekp((long)0, std::ios::beg);
	ofs.write(reinterpret_cast<const char*>(buf), len);

	if (ofs.fail())
	{
		std::cout << "Failed to write the file" << std::endl;
		
	}

}

void TA_store_pubkey(char* key,size_t len) {

	ofstream outfile;
	string path;

	path = "C:\\Users\\87973\\source\\repos\\Enclave5\\initial_data\\TA_public.txt";
	//printf("pubkey = %s\n", key);
	outfile.open(path, ios::out);                                                     
	outfile << key;
	outfile << ends;
	outfile << endl;
	outfile.close();

}

void TA_tracing_log(char* log, size_t len) {

	ofstream outfile;
	string path;

	path = "C:\\Users\\87973\\source\\repos\\Enclave5\\initial_data\\TA_log.txt";
	//printf("pubkey = %s\n", key);
	outfile.open(path, ios::app);
	outfile << log;
	outfile << ends;
	outfile << endl;
	outfile.close();

}



static size_t get_file_size(const char* filename)
{
	std::ifstream ifs(filename, std::ios::in | std::ios::binary);
	if (!ifs.good())
	{
		std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
		return -1;
	}
	ifs.seekg(0, std::ios::end);
	size_t size = (size_t)ifs.tellg();
	return size;
}

static bool read_file_to_buf(const char* filename, uint8_t* buf, size_t bsize)
{
	if (filename == NULL || buf == NULL || bsize == 0)
		return false;
	std::ifstream ifs(filename, std::ios::binary | std::ios::in);
	if (!ifs.good())
	{
		std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
		return false;
	}
	ifs.read(reinterpret_cast<char*> (buf), bsize);
	if (ifs.fail())
	{
		std::cout << "Failed to read the file \"" << filename << "\"" << std::endl;
		return false;
	}
	return true;
}

static bool TA_gen_and_seal_prikey() {

	sgx_enclave_id_t	eid;
	sgx_status_t		ret = SGX_SUCCESS;
	sgx_launch_token_t	token = { 0 };

	int updated = 0;
	char buffer[MAX_BUF_LEN] = "Hello World!";


	//创建包含token的enclave容器
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("APP:error %#x ,failed to create enclave .\n", ret);
		return -1;
	}

	//Enclave CALL(ECALL) 启动enclave容器
	//foo(eid, buffer, MAX_BUF_LEN);
	//printf("%s", buffer);

	TA_gen_prikey(eid);//生成私钥并加密


	//销毁enclave容器
	sgx_destroy_enclave(eid);
		


	std::cout << "Sealing data succeeded." << std::endl;
	return true;
}

static bool TA_read_and_unseal_prikey() {
	sgx_enclave_id_t	eid;
	sgx_status_t		ret = SGX_SUCCESS;
	sgx_launch_token_t	token = { 0 };

	int updated = 0;
	char buffer[MAX_BUF_LEN] = "Hello World!";


	//创建包含token的enclave容器
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("APP:error %#x ,failed to create enclave .\n", ret);
		return -1;
	}

	//解密私钥文件

	size_t fsize = get_file_size("C:\\Users\\87973\\source\\repos\\Enclave5\\initial_data\\TA_private.txt");
	if (fsize == (size_t)-1)
	{
		std::cout << "Failed to get the file size " << std::endl;
		sgx_destroy_enclave(eid);
		return false;
	}
	uint8_t* temp_buf = (uint8_t*)malloc(fsize);
	if (temp_buf == NULL)
	{
		std::cout << "Out of memory" << std::endl;
		sgx_destroy_enclave(eid);
		return false;
	}
	if (read_file_to_buf("C:\\Users\\87973\\source\\repos\\Enclave5\\initial_data\\TA_private.txt", temp_buf, fsize) == false)
	{
		std::cout << "Failed to read the sealed data blob from " << std::endl;
		free(temp_buf);
		sgx_destroy_enclave(eid);
		return false;
	}
	sgx_status_t retval;

	char TA_prikey[MAX_BUF_LEN]="Hello World!";
	
	ret = unseal_data(eid, &retval, temp_buf, fsize, TA_prikey, MAX_BUF_LEN);

	printf("TA_priv_key:%s \n", TA_prikey);
	printf("TA_prikey_size = %d\n", strlen(TA_prikey));

	if (ret != SGX_SUCCESS)
	{

		free(temp_buf);
		sgx_destroy_enclave(eid);
		return false;
	}
	else if (retval != SGX_SUCCESS)
	{

		free(temp_buf);
		sgx_destroy_enclave(eid);
		return false;
	}
	free(temp_buf);
	sgx_destroy_enclave(eid);
	std::cout << "Unseal succeeded." << std::endl;

	//销毁enclave容器
	sgx_destroy_enclave(eid);
	return true;

}

void TA_verifying_and_tracing() {

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

	//读取用户上传相遇信息  ,,假设用户2确诊 ，上传用户1发来的相遇信息
	string ID_1met2 = ReadLine("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2_EH\\ID_3met_2.txt", 1);
	//   cout << "ID_1met2:" << ID_1met2 << endl;

	string id_1met2_1 = ReadLine("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2_EH\\ID_3met_2.txt", 2);
	//  cout << "id_1met2_1:" << id_1met2_1 << endl;

	string id_1met2_2 = ReadLine("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2_EH\\ID_3met_2.txt", 3);
	// cout << "T:" << T << endl;

	string T = ReadLine("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2_EH\\ID_3met_2.txt", 4);
	// cout << "T:" << T << endl;

	string sign_str = ReadLine("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2_EH\\ID_3met_2.txt", 5);
	//  cout << "sign_str：" << sign_str << endl;

	string r_kpub = ReadLine("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2met3_upload.txt", 1);
	//  cout << "r_kpub:" << r_kpub << endl;

	string r_w = ReadLine("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2met3_upload.txt", 2);
	//cout << "r_w" << r_w << endl;

	string id1 = ReadLine("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2met3_upload.txt", 3);
	//  cout << "id1:" << id1 << endl;

	string id2 = ReadLine("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2met3_upload.txt", 4);
	//  cout << "id2:" << id2 << endl;

	BIGNUM* sign;
	sign = BN_new();
	char* sign_c = new char[sign_str.length()];
	strcpy(sign_c, sign_str.c_str());
	BN_hex2bn(&sign, sign_c);

	//获取用户相遇匿名第一部分
	char* id_1met2_1_c = new char[id_1met2_1.length()];
	strcpy(id_1met2_1_c, id_1met2_1.c_str());
	EC_POINT* ID_1met2_1 = NULL;
	ID_1met2_1 = EC_POINT_new(group);
	EC_POINT_hex2point(group, id_1met2_1_c, ID_1met2_1, ctx);

	char* id1_c = new char[id1.length()];
	strcpy(id1_c, id1.c_str());
	EC_POINT* ID1 = NULL;
	ID1 = EC_POINT_new(group);
	EC_POINT_hex2point(group, id1_c, ID1, ctx);

	char* id2_c = new char[id2.length()];
	strcpy(id2_c, id2.c_str());
	EC_POINT* ID2 = NULL;
	ID2 = EC_POINT_new(group);
	EC_POINT_hex2point(group, id2_c, ID2, ctx);

	char* r_w_c = new char[r_w.length()];
	strcpy(r_w_c, r_w.c_str());
	EC_POINT* r_W = NULL;
	r_W = EC_POINT_new(group);
	EC_POINT_hex2point(group, r_w_c, r_W, ctx);

	char* r_kpub_c = new char[r_kpub.length()];
	strcpy(r_kpub_c, r_kpub.c_str());
	EC_POINT* r_Kpub = NULL;
	r_Kpub = EC_POINT_new(group);
	EC_POINT_hex2point(group, r_kpub_c, r_Kpub, ctx);

	//验证左右等式是否相等
	EC_POINT* equation_left = NULL;
	EC_POINT* equation_right = NULL;
	equation_left = EC_POINT_new(group);
	equation_right = EC_POINT_new(group);

	//计算alpha和beta的值

	//计算阿尔法
	char* ID_1met2_char = new char[ID_1met2.length()];
	strcpy(ID_1met2_char, ID_1met2.c_str());
	unsigned char hash_ID_1met2[20] = { 0 };
	SHA1((const unsigned char*)ID_1met2_char, strlen(ID_1met2_char), hash_ID_1met2);
	BIGNUM* alpha = BN_new();
	BN_bin2bn(hash_ID_1met2, 20, alpha);

	//计算贝塔
	ID_1met2 = ID_1met2.substr(0, ID_1met2.length() - 1);
	string ID_1met2_T = ID_1met2 + T;
	char* ID_1met2_T_char = new char[ID_1met2_T.length()];
	strcpy(ID_1met2_T_char, ID_1met2_T.c_str());
	unsigned char hash_ID_1met2_T[20] = { 0 };
	SHA1((const unsigned char*)ID_1met2_T_char, strlen(ID_1met2_T_char), hash_ID_1met2_T);
	BIGNUM* beta = BN_new();
	BN_bin2bn(hash_ID_1met2_T, 20, beta);

	//左等式
	EC_POINT_mul(group, equation_left, NULL, ID2, sign, ctx);

	//右等式
	EC_POINT_mul(group, r_W, NULL, r_W, beta, ctx);
	EC_POINT_mul(group, r_Kpub, NULL, r_Kpub, alpha, ctx);
	EC_POINT_add(group, equation_right, r_W, ID_1met2_1, ctx);
	EC_POINT_add(group, equation_right, equation_right, r_Kpub, ctx);

	if (!EC_POINT_cmp(group, equation_right, equation_left, ctx)) {
		cout << "TA verify success" << endl;
	}
	else {
		cout << "TA verify fail" << endl;
	}


	//在sgx中去匿名

	sgx_enclave_id_t	eid;
	sgx_status_t		ret = SGX_SUCCESS;
	sgx_launch_token_t	token = { 0 };

	int updated = 0;
	char buffer[MAX_BUF_LEN] = "Hello World!";


	//创建包含token的enclave容器
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("APP:error %#x ,failed to create enclave .\n", ret);
		
	}
	//解密私钥文件

	size_t fsize = get_file_size("C:\\Users\\87973\\source\\repos\\Enclave5\\initial_data\\TA_private.txt");
	if (fsize == (size_t)-1)
	{
		std::cout << "Failed to get the file size " << std::endl;
		sgx_destroy_enclave(eid);
		
	}
	uint8_t* temp_buf = (uint8_t*)malloc(fsize);
	if (temp_buf == NULL)
	{
		std::cout << "Out of memory" << std::endl;
		sgx_destroy_enclave(eid);
		
	}
	if (read_file_to_buf("C:\\Users\\87973\\source\\repos\\Enclave5\\initial_data\\TA_private.txt", temp_buf, fsize) == false)
	{
		std::cout << "Failed to read the sealed data blob from " << std::endl;
		free(temp_buf);
		sgx_destroy_enclave(eid);
		
	}
	sgx_status_t retval;

	char Tracing_RID[20];
	strcpy(Tracing_RID, id_1met2_2.c_str());
	


	string T2 = CurrentDate();
	char Tracing_T[20];
	strcpy(Tracing_T, T2.c_str());


	ret = TA_tracing(eid, &retval, temp_buf, fsize, id1_c,strlen(id1_c) ,Tracing_RID, strlen(Tracing_RID), Tracing_T, strlen(Tracing_T));

	

	if (ret != SGX_SUCCESS)
	{

		free(temp_buf);
		sgx_destroy_enclave(eid);
		
	}
	else if (retval != SGX_SUCCESS)
	{

		free(temp_buf);
		sgx_destroy_enclave(eid);
		
	}
	free(temp_buf);
	sgx_destroy_enclave(eid);
	std::cout << "Unseal succeeded." << std::endl;

	//销毁enclave容器
	sgx_destroy_enclave(eid);


	EC_GROUP_free(group), group = NULL;
	BN_CTX_free(ctx);
	EC_POINT_free(equation_right);
	EC_POINT_free(equation_left);
	EC_POINT_free(ID_1met2_1);
	EC_POINT_free(r_W);
	EC_POINT_free(r_Kpub);
	EC_POINT_free(ID2);
	EC_POINT_free(ID1);
	BN_free(beta);
	BN_free(alpha);
	BN_free(sign);
}




int main()
{
	int step =6;
	if (step == 0) {

		if (TA_gen_and_seal_prikey() == false)
		{
			std::cout << "Failed to seal the secret and save it to a file." << std::endl;
			return -1;
		}

		// Enclave_Unseal: read the data blob from the file and unseal it.
		if (TA_read_and_unseal_prikey() == false)
		{
			std::cout << "Failed to unseal the data blob." << std::endl;
			return -1;
		}
	}
	
	if (step == 1) {
		user_sk_initial();
	}
	if (step == 2) {
		user_inital();
	}

	if (step == 3) {
		User_Encounter();
	}

	if (step == 4) {
		User_Verify();
	}
	if (step == 5) {
		User_batch_ver();
	}

	if (step == 6) {
		TA_verifying_and_tracing();
		//TA_Tracing();
	}
	return 0;

}



