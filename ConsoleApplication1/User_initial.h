#pragma once
#ifndef USERINITIAL_H_
#define USERINITIAL_H_

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

void user_inital() {
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

    ifstream infile;
    infile.open("C:\\Users\\87973\\source\\repos\\Enclave5\\initial_data\\TA_gama_d.txt", ios::in);//读取TA_gama_d
    //ios::in	输入：文件将允许输入操作。如果文件不存在，打开将失败
    string u_gama_s;

    infile >> u_gama_s;
    char* u_gama_c = new char[u_gama_s.length()];
    strcpy(u_gama_c, u_gama_s.c_str());
    cout << u_gama_c << endl;
    infile.close();

    BIGNUM* u_gama;
    u_gama = BN_new();
    BN_hex2bn(&u_gama, u_gama_c);

    string sk_str = ReadLine("C:\\Users\\87973\\source\\repos\\Enclave5\\initial_data\\User_sk.txt", 1);   //假设用户1
    cout << sk_str << endl;

    BIGNUM* u_kd, * sk;
    u_kd = BN_new();
    sk = BN_new();
    char* sk_c = new char[256];
    strcpy(sk_c, sk_str.c_str());
    BN_hex2bn(&sk, sk_c);

    BN_mod(u_kd, u_gama, sk, ctx);
    cout << BN_bn2hex(u_kd) << endl;

    ///用户存储计算得出的kd
    ofstream outfile;
    outfile.open("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_kd.txt", ios::out);//存私钥。txt
    //ios::out	输出：文件将允许输出操作。如果文件不存在，则创建一个给定名称的空文件
    outfile << BN_bn2hex(u_kd);
    outfile << ends;
    outfile << endl;
    outfile.close();

    //生成5个随机数r，作为5个用户的初始广播匿名
    EC_POINT* ID = NULL;
    ID = EC_POINT_new(group);
    BIGNUM* ri;
    ri = BN_new();
    EC_POINT* W = NULL;
    W = EC_POINT_new(group);
    BIGNUM* w;
    w = BN_new();

    string path;
    for (int i = 0; i < 100; i++) {
        path = "C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_" + to_string(i) + "_ri.txt";
        BN_rand_range(ri, EC_GROUP_get0_order(group));
        outfile.open(path, ios::out);                                                     //存ri。txt...................
        outfile << BN_bn2hex(ri);
        outfile << ends;
        outfile << endl;
        outfile.close();

        path = "C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_" + to_string(i) + "_ID.txt";
        EC_POINT_mul(group, ID, ri, NULL, NULL, ctx);
        outfile.open(path, ios::out);                                                     //存ID。txt.................
        outfile << EC_POINT_point2hex(group, ID, POINT_CONVERSION_UNCOMPRESSED, ctx);
        outfile << ends;
        outfile << endl;
        outfile.close();


        path = "C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_" + to_string(i) + "_w.txt";
        BN_rand_range(w, EC_GROUP_get0_order(group));
        outfile.open(path, ios::out);                                                     //存ri。txt...................
        outfile << BN_bn2hex(w);
        outfile << ends;
        outfile << endl;
        outfile.close();

        path = "C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_" + to_string(i) + "_Ww.txt";
        EC_POINT_mul(group, W, w, NULL, NULL, ctx);
        outfile.open(path, ios::out);                                                     //存ID。txt.................
        outfile << EC_POINT_point2hex(group, W, POINT_CONVERSION_UNCOMPRESSED, ctx);
        outfile << ends;
        outfile << endl;
        outfile.close();

    }
   

    EC_GROUP_free(group), group = NULL;
    EC_POINT_free(ID);
    EC_POINT_free(W);
    BN_CTX_free(ctx);
    BN_free(sk);
    BN_free(u_kd);
    BN_free(u_gama);

}

#endif