#pragma once
#ifndef TATRACING_H_
#define TATRACING_H_

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


#include <string>
#include <iostream>

using namespace std;

char key[] = { 1,2,3,4,5,6,7 };

void encryption(char* c, char key[]) {
	int len = strlen(c);
	for (int i = 0; i < len; i++) {
		c[i] = c[i] ^ key[i % 7];
	}
}
void decode(char* c, char key[]) {
	int len = strlen(c);
	for (int i = 0; i < len; i++) {
		c[i] = c[i] ^ key[i % 7];
	}
}

/*两个字符转换成一个字符，长度为原来的1/2*/
static void Hex2Char(char* szHex, unsigned char* rch)
{
	int i;
	for (i = 0; i < 2; i++)
	{
		if (*(szHex + i) >= '0' && *(szHex + i) <= '9')
			*rch = (*rch << 4) + (*(szHex + i) - '0');
		else if (*(szHex + i) >= 'a' && *(szHex + i) <= 'f')
			*rch = (*rch << 4) + (*(szHex + i) - 'a' + 10);
		else
			break;
	}
}

	

void TA_Tracing() {
	char str[] = "hello world!";
	std::cout << "原文：" << str << std::endl;
	encryption(str, key);
	std::cout << "加密后密文：" << str << std::endl;
	decode(str, key);
	std::cout << "解密后密文：" << str << std::endl;

	string a = "aaa";
	char b[] = "bbb";
	a = a + b;
	cout << a << endl;


	ifstream infile;
	infile.open("C:\\Users\\87973\\source\\repos\\Enclave5\\User_data\\user_2_EH\\ID_12met_2.txt", ios::in);
	//ios::in	输入：文件将允许输入操作。如果文件不存在，打开将失败
	char c_pubkey[2000] = { 0 };
	infile >> c_pubkey;
	cout << c_pubkey << endl;

}




#endif