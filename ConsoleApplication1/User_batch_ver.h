#pragma once
#ifndef USERBATCHVER_H_
#define USERBATCHVER_H_

#include<iostream>
#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include <string>
#include <openssl/pem.h>

#include<conio.h>
#include "sgx_urts.h"
#include "Enclave5_u.h"
#include <fstream>
#include "tainitial.h"
#define random(a,b) (rand()%(b-a)+a)
#define EC_POINT_SIZE 256

using namespace std;




void User_batch_ver() {

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

	//计时
	LARGE_INTEGER  BVMM_s, BVMM_e, BVMM_tc;

    //用户2收到用户i的签名，准备验证，以用户2视角为主体

       //用户2读取自身ri  ，后续不需要读取自身广播ID，直接用ri计算即可
    ifstream infile2;
    infile2.open("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2_ri.txt", ios::in);
    //ios::in	输入：文件将允许输入操作。如果文件不存在，打开将失败
    char r2_c[1000];
    infile2 >> r2_c;
    infile2.close();
    cout << "r2_c:" << r2_c << endl;

    BIGNUM* r2;
    r2 = BN_new();
    BN_hex2bn(&r2, r2_c);
    std::cout << "user_2 ri:" << BN_bn2hex(r2) << endl;
    



    infile2.open("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_kd.txt", ios::in);//读取kd
    char kd_c[1000] = { 0 };
    infile2 >> kd_c;
    infile2.close();
    cout << "kd:" << kd_c << endl;

    BIGNUM* kd;
    kd = BN_new();
    BN_hex2bn(&kd, kd_c);


    // 提前计算
    EC_POINT* ID = NULL;
    ID = EC_POINT_new(group);
    EC_POINT_mul(group, ID, r2, NULL, NULL, ctx);

    //批处理验证多个签名

    const int batch =100;
    string ID_1met2[batch];
    string id_1met2_1[batch];
    string T[batch];
    string sign_str[batch];

    char file[100];
    EC_POINT* W[batch];
    //用户2读取数据
    for (int i = 0; i < batch; i++) {

        strcpy(file, ("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2_EH\\ID_" + to_string(i) + "met_2.txt").c_str());
        cout << file << endl;

        ID_1met2[i] = ReadLine((const char*)file, 1);
        cout << "ID_1met2:" << ID_1met2 [i] << endl;

        id_1met2_1[i] = ReadLine(file, 2);
        cout << "id_1met2_1:" << id_1met2_1 [i] << endl;

        T[i] = ReadLine(file, 4);
        // cout << "T:" << T [i] << endl;

        sign_str[i] = ReadLine(file, 5);
        // cout << "sign_str：" << sign_str[i] << endl;
       //  cout << endl;
        infile2.open("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_" + to_string(i) + "_Ww.txt", ios::in);
        char W_c[1000] = { 0 };
        infile2 >> W_c;
        W[i] = EC_POINT_new(group);
        EC_POINT_hex2point(group, W_c, W[i], ctx);
        infile2.close();
        //cout << "W_w:" << W_c << endl;
    }


    EC_POINT* r_W[batch];
    for (int i = 0; i < batch; i++) {

        r_W[i] = EC_POINT_new(group);
        EC_POINT_mul(group, r_W[i], NULL, W[i], r2, ctx);

    }

    //签名string转换成大数
    BIGNUM* sign[batch];
    for (int i = 0; i < batch; i++) {
        sign[i] = BN_new();
        char* sign_c = new char[sign_str[i].length()];
        strcpy(sign_c, sign_str[i].c_str());
        BN_hex2bn(&sign[i], sign_c);

    }

    //匿名string转换成椭圆曲线的点
    EC_POINT* ID_1met2_1[batch];
    for (int i = 0; i < batch; i++) {

        char* id_1met2_1_c = new char[id_1met2_1[i].length()];
        strcpy(id_1met2_1_c, id_1met2_1[i].c_str());
        ID_1met2_1[i] = EC_POINT_new(group);
        EC_POINT_hex2point(group, id_1met2_1_c, ID_1met2_1[i], ctx);
        // cout << "ID_7met2_1" << EC_POINT_point2hex(group, ID_1met2_1[i], POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;//

    }

    //BVMM计时开始
    QueryPerformanceFrequency(&BVMM_tc);
    QueryPerformanceCounter(&BVMM_s);

    //验证左右等式是否相等

    EC_POINT* equation_left = NULL;
    EC_POINT* equation_right = NULL;

    equation_left = EC_POINT_new(group);
    equation_right = EC_POINT_new(group);

    //左等式

    //生成随机数小正数
    BIGNUM* V[batch];
    int v[batch];
    int v2[batch];
    for (int i = 0; i < batch; i++) {
        v[i] = random(1, 1024);
        v2[i] = v[i];
        V[i] = BN_new();
        BN_dec2bn(&V[i], to_string(v[i]).c_str());
        BN_mul_word(sign[i], v[i]);
    }

    BIGNUM* v_sign = BN_new();
    BN_add(v_sign, sign[0], sign[1]);
    for (int i = 2; i < batch; i++) {
        BN_add(v_sign, v_sign, sign[i]);
    }

    EC_POINT_mul(group, equation_left, NULL, ID, v_sign, ctx);


    //右等式

    BN_CTX* ctx1 = NULL;
    ctx1 = BN_CTX_new();
    
    

    EC_POINT* v_ID[batch];
    for (int i = 0; i < batch; i++) {
        v_ID[i] = EC_POINT_new(group);
        //EC_POINT_mul(group, v_ID[i], NULL, ID_1met2_1[i], V[i], ctx);
        //ec_point_small_mul(v[i], EC_GROUP_get0_generator(group), *v_ID[i], group);
        int a[100];
        int j = 0;
        while (v2[i]) {
            a[j] = v2[i] % 2;
            v2[i] = v2[i] / 2;
            j++;
        }
        EC_POINT* ec_point[100];
        ec_point[0] = EC_POINT_new(group);
        EC_POINT_add(group, ec_point[0], ec_point[0], ID_1met2_1[i], ctx1);
        for (int k = 1; k < j; k++) {
            ec_point[k] = EC_POINT_new(group);
            EC_POINT_add(group, ec_point[k], ec_point[k - 1], ec_point[k - 1], ctx1);
        }
        for (int b = 0; b < j; b++) {
            if (a[b] == 1)EC_POINT_add(group, v_ID[i], v_ID[i], ec_point[b], ctx1);
        }
    }

    //计算alpha【】
    BIGNUM* alpha[batch];
    for (int i = 0; i < batch; i++) {
        alpha[i] = BN_new();
        char* ID_1met2_char = new char[ID_1met2[i].length()];
        strcpy(ID_1met2_char, ID_1met2[i].c_str());
        unsigned char hash_ID_1met2[20] = { 0 };
        SHA1((const unsigned char*)ID_1met2_char, strlen(ID_1met2_char), hash_ID_1met2);
        BN_bin2bn(hash_ID_1met2, 20, alpha[i]);


    }


    //计算贝塔

    BIGNUM* beta[batch];
    for (int i = 0; i < batch; i++) {
        beta[i] = BN_new();
        ID_1met2[i] = ID_1met2[i].substr(0, ID_1met2[i].length() - 1);
        string ID_1met2_T = ID_1met2[i] + T[i];
        char* ID_1met2_T_char = new char[ID_1met2_T.length()];
        strcpy(ID_1met2_T_char, ID_1met2_T.c_str());
        unsigned char hash_ID_1met2_T[20] = { 0 };
        SHA1((const unsigned char*)ID_1met2_T_char, strlen(ID_1met2_T_char), hash_ID_1met2_T);
        BN_bin2bn(hash_ID_1met2_T, 20, beta[i]);
    }

    for (int i = 0; i < batch; i++) {
        BN_mul_word(alpha[i], v[i]);
    }

    BIGNUM* v_alpha = BN_new();
    BN_add(v_alpha, alpha[0], alpha[1]);
    for (int i = 2; i < batch; i++) {
        BN_add(v_alpha, v_alpha, alpha[i]);
    }
    BN_mul(v_alpha, v_alpha, r2, ctx);
    BN_mul(v_alpha, v_alpha, kd, ctx);

    EC_POINT_mul(group, equation_right, v_alpha, NULL, NULL, ctx);

    for (int i = 0; i < batch; i++) {
        EC_POINT_add(group, equation_right, equation_right, v_ID[i], ctx);
    }

    BIGNUM* v_beta = BN_new();
    for (int i = 0; i < batch; i++) {
        BN_mul_word(beta[i], v[i]);
        EC_POINT_mul(group, W[i], NULL, W[i], beta[i], ctx);
    }

    EC_POINT* v_b_W = NULL;
    v_b_W = EC_POINT_new(group);
    EC_POINT_add(group, v_b_W, W[0], W[1], ctx);
    for (int i = 2; i < batch; i++) {
        EC_POINT_add(group, v_b_W, v_b_W, W[i], ctx);
    }
    EC_POINT_mul(group, v_b_W, NULL, v_b_W, r2, ctx);
    EC_POINT_add(group, equation_right, equation_right, v_b_W, ctx);

    QueryPerformanceCounter(&BVMM_e);
    double time_3 = (double)(BVMM_e.QuadPart - BVMM_s.QuadPart) / (double)BVMM_tc.QuadPart * 1000;
    cout << "批处理签名验证 time = " << time_3 << "ms" << endl;

    if (!EC_POINT_cmp(group, equation_right, equation_left, ctx)) {
        cout << "batch anomity verify success" << endl;
    }
    else {
        cout << "batch anomity verify fail" << endl;
    }

    //用户确诊后，上传相遇信息
    EC_POINT* r_Kpub = NULL;
    r_Kpub = EC_POINT_new(group);
    EC_POINT_mul(group, r_Kpub, r2, NULL, NULL, ctx);
    EC_POINT_mul(group, r_Kpub, NULL, r_Kpub, kd, ctx);



    BIGNUM* r2_inverse = NULL;
    r2_inverse = BN_new();
    BN_mod_inverse(r2_inverse, r2, EC_GROUP_get0_order(group), ctx);



    EC_POINT* ID_i[batch];
    for (int i = 0; i < batch; i++) {

        ID_i[i] = EC_POINT_new(group);
        EC_POINT_mul(group, ID_i[i], NULL, ID_1met2_1[i], r2_inverse, ctx);

    }



    ofstream outfile;
    for (int i = 0; i < batch; i++) {

        outfile.open("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2met" + to_string(i) + "_upload.txt", ios::out);        //r*Kpub     
        outfile << EC_POINT_point2hex(group, r_Kpub, POINT_CONVERSION_UNCOMPRESSED, ctx);
        outfile << ends;
        outfile << endl;


        outfile << EC_POINT_point2hex(group, r_W[i], POINT_CONVERSION_UNCOMPRESSED, ctx);           //r*W
        outfile << ends;
        outfile << endl;


        outfile << EC_POINT_point2hex(group, ID_i[i], POINT_CONVERSION_UNCOMPRESSED, ctx);         //上传发送者ID
        outfile << ends;
        outfile << endl;

        outfile << EC_POINT_point2hex(group, ID, POINT_CONVERSION_UNCOMPRESSED, ctx);         //上传自身ID
        outfile << ends;
        outfile << endl;

        outfile.close();



    }

    EC_GROUP_free(group), group = NULL;

    BN_CTX_free(ctx);
    for (int i = 0; i < batch; i++) {
        EC_POINT_free(ID_i[i]);
        EC_POINT_free(r_W[i]);
        
        BN_free(beta[i]);
        BN_free(alpha[i]);

        EC_POINT_free(v_ID[i]);
        EC_POINT_free(ID_1met2_1[i]);
       
        BN_free(V[i]);
        BN_free(sign[i]);
     
    }
    EC_POINT_free(r_Kpub);

    
    EC_POINT_free(v_b_W);

    EC_POINT_free(ID);
    BN_free(r2_inverse);
    BN_free(v_beta);
    
    BN_free(v_alpha);

    EC_POINT_free(equation_left);
    EC_POINT_free(equation_right);

    BN_free(v_sign);
   
    BN_free(kd);
    
}



#endif