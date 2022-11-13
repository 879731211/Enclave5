#pragma once
#ifndef USERENCOUNTER_H_
#define USERENCOUNTER_H_

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

using namespace std;

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
        case '0': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a0[j]; break;
        case '1': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a1[j]; break;
        case '2': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a2[j]; break;
        case '3': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a3[j]; break;
        case '4': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a4[j]; break;
        case '5': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a5[j]; break;
        case '6': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a6[j]; break;
        case '7': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a7[j]; break;
        case '8': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a8[j]; break;
        case '9': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a9[j]; break;
        case 'A': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a10[j]; break;
        case 'B': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a11[j]; break;
        case 'C': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a12[j]; break;
        case 'D': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a13[j]; break;
        case 'E': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a14[j]; break;
        case 'F': for (int j = 0; j < 4; j++)bin[i * 4 + j] = a15[j]; break;
        }
    }

    return bin;

}

void User_Encounter() {

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
    LARGE_INTEGER AIDM_s, AIDM_e, AIDM_tc;

    //获取TA公钥
    EC_POINT* pub_key = NULL;
    pub_key = EC_POINT_new(group);


    ifstream infile;
    infile.open("C:\\Users\\87973\\source\\repos\\Enclave5\\initial_data\\TA_public.txt", ios::in);
    //ios::in	输入：文件将允许输入操作。如果文件不存在，打开将失败
    char c_pubkey[1000] = { 0 };
    infile >> c_pubkey;
    infile.close();
    EC_POINT_hex2point(group, c_pubkey, pub_key, ctx);

    //cout << "TA_pub_key:" << EC_POINT_point2hex(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;

    //用户相遇，生成相遇匿名；  多个用户相遇用户2
    
    const int user_sum = 100;
    int user_nums[user_sum];
    for (int i = 0; i < user_sum; i++) {
        user_nums[i] = i;
    }
    char ri_c[user_sum][1000] = { 0 };

    for (int i = 0; i < user_sum; i++) {
        infile.open("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_" + to_string(user_nums[i]) + "_ri.txt", ios::in);
        infile >> ri_c[i];
        infile.close();
    }
   
    BIGNUM* ri[user_sum];
    for (int i = 0; i < user_sum; i++) {
        ri[i] = BN_new();
        BN_hex2bn(&ri[i], ri_c[i]);
        //cout << "user_" + to_string(user_nums[i]) + "_ri:" << BN_bn2hex(ri[i]) << endl;
    }


    //首先多个用户 获取相遇用户匿名ID，假设读取用户2的ID
    EC_POINT* ID = NULL;
    ID = EC_POINT_new(group);
    infile.open("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2_ID.txt", ios::in);
    //ios::in	输入：文件将允许输入操作。如果文件不存在，打开将失败
    char u_ID[1000] = { 0 };
    infile >> u_ID;
    infile.close();
    EC_POINT_hex2point(group, u_ID, ID, ctx);

    cout << "user_2 ID:" << EC_POINT_point2hex(group, ID, POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;
   
    cout << endl;


    //读取用户w，后续计算签名需要使用
    char w_c[user_sum][1000] = { 0 };
    for (int i = 0; i < user_sum; i++) {
        infile.open("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_" + to_string(user_nums[i]) + "_w.txt", ios::in);//读取多个用户 w
        infile >> w_c[i];
        infile.close();
    }
    BIGNUM* w[user_sum];
    for (int i = 0; i < user_sum; i++) {
        w[i] = BN_new();
        BN_hex2bn(&w[i], w_c[i]);
       // cout << "user_" + to_string(user_nums[i]) + "_ w:" << BN_bn2hex(w[i]) << endl;
        infile.close();
    }

    cout << endl;

    infile.open("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_kd.txt", ios::in);//读取kd
    char kd_c[1000] = { 0 };
    infile >> kd_c;
    infile.close();

    BIGNUM* kd;
    kd = BN_new();
    BN_hex2bn(&kd, kd_c);
    cout << "kd:" << BN_bn2hex(kd) << endl;

    //获取匿名生成时间
    string T[user_sum];

    char* id_1met2_1[user_sum];
    //相遇匿名ID=id_1||id_2   ，这里都是假设用户1相遇用户2，实际上是用户i相遇用户2
    string ID_1met2[user_sum];

    string id_2_str[user_sum];

    BIGNUM* sign[user_sum];

    double ttt = 0;

    for (int i = 0; i < user_sum; i++) {

        //第i个用户的时间
        T[i] = CurrentDate();

        //RID
        const char RID[] = "15918562471";
        BIGNUM* rid = BN_new();
        BN_dec2bn(&rid, RID);

        string af = GetBinaryStringFromHexString(BN_bn2hex(rid));
        //cout << "USER's RID:" << endl;              //输出耗时多1ms-4ms
       // cout << af << endl;

        //RID字符串转成int数组方便异或
        int* intaf = new int[af.length()];
        for (int j = 0; j < af.length(); j++) {
            intaf[j] = af[j] - '0';
        }
        //cout << "af:"<<af << endl;

           //AIDM计时开始
        QueryPerformanceFrequency(&AIDM_tc);
        QueryPerformanceCounter(&AIDM_s);

        //用户1生成相遇ID_1met2；
        EC_POINT* ID_1met2_1 = NULL;
        ID_1met2_1 = EC_POINT_new(group);

        EC_POINT_mul(group, ID_1met2_1, NULL, ID, ri[i], ctx);

        id_1met2_1[i] = EC_POINT_point2hex(group, ID_1met2_1, POINT_CONVERSION_UNCOMPRESSED, ctx);
        string id_1met2_1_str = GetBinaryStringFromHexString(id_1met2_1[i]);

        //id中的哈希部分
        EC_POINT* ID_h = NULL;
        ID_h = EC_POINT_new(group);
        EC_POINT_mul(group, ID_h, NULL, pub_key, ri[i], ctx);

        const unsigned char* id_h = (const unsigned char*)(EC_POINT_point2hex(group, ID_h, POINT_CONVERSION_COMPRESSED, ctx));

        unsigned char hash_idh[20] = { 0 };
        SHA1(id_h, strlen((char*)id_h), hash_idh);


        //hash字符数组转成大数
        BIGNUM* idh = BN_new();
        BN_bin2bn(hash_idh, 20, idh);

        //将hash的大数形式转成二进制
        string bf = GetBinaryStringFromHexString(BN_bn2hex(idh));

        int* intbf = new int[bf.length()];
        for (int i = 0; i < bf.length(); i++) {
            intbf[i] = bf[i] - '0';
        }



        //RID与hash的异或
        int* id_2 = new int[af.length()];
        for (int k = 0; k < af.length(); k++) {
            id_2[k] = intbf[k] ^ intaf[k];
        }

       

        //id_2的string形式 
        for (int j = 0; j < af.length(); j++) {
            id_2_str[i] = id_2_str[i] + to_string(id_2[j]);            ///耗时0.6ms      结构体能省去
        }

        


        ID_1met2[i] = id_1met2_1_str + id_2_str[i];


        //用户1，准备对消息签名，此处消息省略RSSI

        //计算阿尔法
        char* ID_1met2_char = new char[ID_1met2[i].length()];
        strcpy(ID_1met2_char, ID_1met2[i].c_str());

        unsigned char hash_ID_1met2[20] = { 0 };
        SHA1((const unsigned char*)ID_1met2_char, strlen(ID_1met2_char), hash_ID_1met2);

        BIGNUM* alpha = BN_new();
        BN_bin2bn(hash_ID_1met2, 20, alpha);


        //计算贝塔
        string ID_1met2_T = ID_1met2[i] + T[i];

        char* ID_1met2_T_char = new char[ID_1met2_T.length()];
        strcpy(ID_1met2_T_char, ID_1met2_T.c_str());
        // cout << "ID_1met2_T_char:" << ID_1met2_T_char << endl;
        // cout << endl;

        unsigned char hash_ID_1met2_T[20] = { 0 };
        SHA1((const unsigned char*)ID_1met2_T_char, strlen(ID_1met2_T_char), hash_ID_1met2_T);

        BIGNUM* beta = BN_new();
        BN_bin2bn(hash_ID_1met2_T, 20, beta);


     


        //开始正式计算签名

        BIGNUM* way = BN_new();
        sign[i] = BN_new();
        BN_mul(way, w[i], beta, ctx);
        BN_add(sign[i], way, ri[i]);
        BN_mul(way, kd, alpha, ctx);
        BN_mod_add(sign[i], sign[i], way, EC_GROUP_get0_order(group), ctx);

        //AIDM计时结束
        QueryPerformanceCounter(&AIDM_e);
        double time_1 = (double)(AIDM_e.QuadPart - AIDM_s.QuadPart) / (double)AIDM_tc.QuadPart * 1000;

        ttt = ttt + time_1;

        BN_free(way);
        BN_free(beta);
        BN_free(alpha);
        BN_free(idh);
        EC_POINT_free(ID_h);
        BN_free(rid);
        EC_POINT_free(ID_1met2_1);


    }

    cout << "单个匿名生成和签名 time = " << ttt / (double)user_sum << "ms" << endl;

    ofstream outfile;
    for (int i = 0; i < user_sum; i++) {
        outfile.open("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2_EH\\ID_" + to_string(user_nums[i]) + "met_2.txt", ios::out);//存相遇匿名。txt
    //ios::out	输出：文件将允许输出操作。如果文件不存在，则创建一个给定名称的空文件
        outfile << ID_1met2[i];            //总体ID
        outfile << ends;
        outfile << endl;

        outfile << id_1met2_1[i];              //ID_1
        outfile << ends;
        outfile << endl;

        outfile << id_2_str[i];                  //ID_2
        outfile << ends;
        outfile << endl;

        outfile << T[i];                  //T
        outfile << ends;
        outfile << endl;

        outfile << BN_bn2hex(sign[i]);                  //sign
        outfile << ends;
        outfile << endl;

        outfile.close();
    }


    EC_GROUP_free(group), group = NULL;


    BN_CTX_free(ctx);


    BN_free(kd);
    for (int i = 0; i < user_sum; i++) {
        BN_free(ri[i]);
        BN_free(w[i]);
       
        BN_free(sign[i]);
    }

    EC_POINT_free(pub_key);
    EC_POINT_free(ID);

}
#endif