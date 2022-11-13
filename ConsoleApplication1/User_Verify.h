#pragma once
#ifndef USERVERIFY_H_
#define USERVERIFY_H_

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

void User_Verify() {

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
    LARGE_INTEGER  SVOM_s, SVOM_e, SVOM_tc;

    //用户2收到用户1的签名，准备验证，以用户2视角为主体

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

    //验证一个签名
    string ID_1met2 = ReadLine("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2_EH\\ID_1met_2.txt", 1);
    cout << "ID_1met2:" << ID_1met2 << endl;

    string id_1met2_1 = ReadLine("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2_EH\\ID_1met_2.txt", 2);
    cout << "id_1met2_1:" << id_1met2_1 << endl;

    string T = ReadLine("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2_EH\\ID_1met_2.txt", 4);
    cout << "T:" << T << endl;

    string sign_str = ReadLine("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2_EH\\ID_1met_2.txt", 5);
    cout << "sign_str：" << sign_str << endl;

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
    cout << "ID_1met2_1" << EC_POINT_point2hex(group, ID_1met2_1, POINT_CONVERSION_UNCOMPRESSED, ctx);

    //获取用户1 的 W
    EC_POINT* W = NULL;
    W = EC_POINT_new(group);
    infile2.open("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_1_Ww.txt", ios::in);
    //ios::in	输入：文件将允许输入操作。如果文件不存在，打开将失败
    char W_c[1000] = { 0 };
    infile2 >> W_c;
    cout << "W_w:" << W_c << endl;
    EC_POINT_hex2point(group, W_c, W, ctx);

    infile2.close();

    //验证
        // 
        // 提前计算
    EC_POINT* ID = NULL;
    ID = EC_POINT_new(group);
    EC_POINT_mul(group, ID, r2, NULL, NULL, ctx);

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
  
    //SVOM计时开始
    QueryPerformanceFrequency(&SVOM_tc);
    QueryPerformanceCounter(&SVOM_s);

    EC_POINT_mul(group, equation_left, NULL, ID, sign, ctx);

    BIGNUM* way;
    way = BN_new();
    BN_mul(way, alpha, r2, ctx);
    BN_mul(way, way, kd, ctx);
    EC_POINT_mul(group, equation_right, way, NULL, NULL, ctx);

    EC_POINT_add(group, equation_right, equation_right, ID_1met2_1, ctx);
    EC_POINT* Way = NULL;


    Way = EC_POINT_new(group);



    BN_mul(way, beta, r2, ctx);

    EC_POINT_mul(group, Way, NULL, W, way, ctx);

    EC_POINT_add(group, equation_right, equation_right, Way, ctx);

    //SVOM计时结束
    QueryPerformanceCounter(&SVOM_e);
    double time_2 = (double)(SVOM_e.QuadPart - SVOM_s.QuadPart) / (double)SVOM_tc.QuadPart * 1000;
    cout << "单个匿名验证 time = " << time_2 << "ms" << endl;

    if (!EC_POINT_cmp(group, equation_right, equation_left, ctx)) {
        cout << "anomity verify success" << endl;
    }
    else {
        cout << "anomity verify fail" << endl;
    }


    EC_POINT_free(Way);
    BN_free(way);
    BN_free(beta);
    BN_free(alpha);
    EC_POINT_free(equation_left);
    EC_POINT_free(equation_right);
    EC_POINT_free(ID);
    EC_POINT_free(W);
    EC_POINT_free(ID_1met2_1);
    BN_free(sign);

    EC_GROUP_free(group), group = NULL;


    BN_CTX_free(ctx);


}

#endif