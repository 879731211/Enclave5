#pragma once
#ifndef TAINITIAL_H_
#define TAINITIAL_H_
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

#include <chrono>
#define random(a,b) (rand()%(b-a)+a)
#define EC_POINT_SIZE 256

using namespace std;


void printHex(const unsigned char* pBuf, int nLen)
{
    for (int i = 0; i < nLen; i++)
    {
        printf("%02X", pBuf[i]);
    }
    printf("\n");
}

string GetBinaryStringFromHexString(string strHex)
{
    string sReturn = "";
    unsigned int len = strHex.length();
    for (unsigned int i = 0; i < len; i++)
    {
        switch (strHex[i])
        {
        case '0': sReturn.append("0000"); break;
        case '1': sReturn.append("0001"); break;
        case '2': sReturn.append("0010"); break;
        case '3': sReturn.append("0011"); break;
        case '4': sReturn.append("0100"); break;
        case '5': sReturn.append("0101"); break;
        case '6': sReturn.append("0110"); break;
        case '7': sReturn.append("0111"); break;
        case '8': sReturn.append("1000"); break;
        case '9': sReturn.append("1001"); break;
        case 'A': sReturn.append("1010"); break;
        case 'B': sReturn.append("1011"); break;
        case 'C': sReturn.append("1100"); break;
        case 'D': sReturn.append("1101"); break;
        case 'E': sReturn.append("1110"); break;
        case 'F': sReturn.append("1111"); break;
        }
    }
    return sReturn;
}
string ReadLine(const char* filename, int line)
{
    int i = 0;
    string temp;
    fstream file;
    file.open(filename, ios::in);

    if (line <= 0)
    {
        return "Error 1: 行数错误，不能为0或负数。";
    }

    if (file.fail())
    {
        return "Error 2: 文件不存在。";
    }

    while (getline(file, temp) && i < line - 1)
    {
        i++;
    }

    file.close();
    return temp;
}

string CurrentDate()
{
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    char buf[100] = { 0 };
    std::strftime(buf, sizeof(buf), "%Y-%m-%d-%H-%M-%S", std::localtime(&now));
    return buf;
}



void user_sk_initial() {
    int nid = 0;
    EC_GROUP* group = NULL;
    nid = OBJ_sn2nid("SM2");
    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        printf("EC_GROUP_new_by_curve_name err!\n");
     
    }

    //计算用户域密钥
    //BIGNUM* sk1, * sk2, * sk3;
    const int n = 100;
    BIGNUM* sk[n];  //
    BIGNUM* SK;
    SK = BN_new();
    ofstream outfile;
    BN_CTX* ctx = NULL;
    ctx = BN_CTX_new();

    outfile.open("C:\\Users\\87973\\source\\repos\\Enclave5\\initial_data\\User_sk.txt", ios::out);//存用户sk。txt
   //ios::out	输出：文件将允许输出操作。如果文件不存在，则创建一个给定名称的空文件

    for (int i = 0; i < n; i++) {
        sk[i] = BN_new();
        BN_generate_prime(sk[i], 256, 1, NULL, NULL, NULL, NULL);
        //  printf("sk%d", i);
        //  printf(" : % s \n", BN_bn2hex(sk[i]));
        outfile << BN_bn2hex(sk[i]);
        outfile << ends;
        outfile << endl;
    }
    cout << endl;

    outfile.close();

    //找出最小sk
    BIGNUM* min;
    min = BN_new();
    min = sk[0];
    for (int i = 1; i < n; i++) {

        if (BN_cmp(min, sk[i]) == 1)  min = sk[i];

    }

    //sigma,xi,yi.
    BIGNUM* sigma_g;   //
    sigma_g = BN_new();

    BN_mul(sigma_g, sk[0], sk[1], ctx);
    for (int i = 2; i < n; i++) {
        BN_mul(sigma_g, sigma_g, sk[i], ctx);
    }
    // printf("sigma_g:%s \n", BN_bn2hex(sigma_g));
    cout << endl;

    BIGNUM* x[n], * rm, * y[n];
    for (int i = 0; i < n; i++) {
        x[i] = BN_new();
        y[i] = BN_new();
    }
    rm = BN_new();
    for (int i = 0; i < n; i++) {
        BN_div(x[i], rm, sigma_g, sk[i], ctx);
        BN_mod_inverse(y[i], x[i], sk[i], ctx);

    }

    //u
    BIGNUM* u, * xxxx[n];
    u = BN_new();

    for (int i = 0; i < n; i++) {
        xxxx[i] = BN_new();
        BN_mul(xxxx[i], x[i], y[i], ctx);

    }
    BN_add(u, xxxx[0], xxxx[1]);
    for (int i = 2; i < n; i++) {
        BN_add(u, u, xxxx[i]);
    }
    cout << endl;
    /*

    */
    BIGNUM* kd;
    kd = BN_new();
    //BN_dec2bn(&kd, "30");
    BN_rand_range(kd, min);
    //  printf("kd:%s \n", BN_bn2hex(kd));
    cout << endl;

    //计算域公密钥
    BIGNUM* gama_d;
    gama_d = BN_new();
    BN_mul(gama_d, kd, u, ctx);
    //   printf("gama:%s \n", BN_bn2hex(gama_d));
    cout << endl;

    outfile.open("C:\\Users\\87973\\source\\repos\\Enclave5\\initial_data\\TA_gama_d.txt", ios::out);//存域公钥：kd*u。txt
    //ios::out	输出：文件将允许输出操作。如果文件不存在，则创建一个给定名称的空文件
    outfile << BN_bn2hex(gama_d);
    outfile << ends;
    outfile << endl;
    outfile.close();

    //K_pub生成
    EC_POINT* K_pub = NULL;
    K_pub = EC_POINT_new(group);
    EC_POINT_mul(group, K_pub, kd, NULL, NULL, ctx);

    outfile.open("C:\\Users\\87973\\source\\repos\\Enclave5\\initial_data\\TA_kd.txt", ios::out);//存kd。txt
    //ios::out	输出：文件将允许输出操作。如果文件不存在，则创建一个给定名称的空文件
    outfile << BN_bn2hex(kd);
    outfile << ends;
    outfile << endl;
    outfile.close();


    unsigned char buf[65];
    unsigned long buflen = 65;
    EC_POINT_point2oct(group, K_pub, POINT_CONVERSION_UNCOMPRESSED, buf, buflen, NULL);
    /*
     EC_POINT_oct2point(group, K_pub_1, buf, buflen, NULL);
    if (EC_POINT_cmp(group, K_pub, K_pub_1, NULL) == 0)cout << "same" << endl;
    将oct转为点
    */

    outfile.open("C:\\Users\\87973\\source\\repos\\Enclave5\\initial_data\\TA_K_pub.txt", ios::out);   //存K_pub。txt
    //ios::out	输出：文件将允许输出操作。如果文件不存在，则创建一个给定名称的空文件
    outfile << buf;
    outfile << ends;
    outfile << endl;
    outfile.close();

    EC_GROUP_free(group), group = NULL;
    EC_POINT_free(K_pub);

    BN_CTX_free(ctx);
    for (int i = 0; i < n; i++) {
        BN_free(sk[i]);
        BN_free(x[i]);
        BN_free(y[i]);
        BN_free(xxxx[i]);
    }
    BN_free(SK);
    BN_free(sigma_g);
    BN_free(rm);
    BN_free(u);
    BN_free(kd);
    BN_free(gama_d);


   
}
#endif