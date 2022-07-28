#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <conio.h>
#include <io.h>
#pragma warning(disable:4996)

//***************************************************************************************************************
//SHA-256 코드
//SHA-256 코드는 학생 본인이 작성하지 않음.
#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdlib.h>
#include <memory.h>

#define SHA256_BLOCK_SIZE 32
#define MAXSIZE 1000000000


typedef struct {
	unsigned char data[64];
	int datalen;
	unsigned long long bitlen;
	int state[8];
} SHA256_CTX;

char Signature[] = {"EncryptedByCino"};
int KeyDepth = 1;

void sha256_init(SHA256_CTX* ctx);
void sha256_update(SHA256_CTX* ctx, const unsigned char data[], size_t len);
void sha256_final(SHA256_CTX* ctx, unsigned char hash[]);

#endif

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const int k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(SHA256_CTX* ctx, const unsigned char data[])
{
	int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for (; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_init(SHA256_CTX* ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX* ctx, const unsigned char data[], size_t len)
{
	int i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_final(SHA256_CTX* ctx, unsigned char hash[])
{
	int i;

	i = ctx->datalen;

	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	for (i = 0; i < 4; ++i) {
		hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

//SHA-256 메인 함수
void SHA256(unsigned char string[], unsigned char hash[]) {
	SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, string, strlen(string));
	sha256_final(&ctx, hash);
}
//***************************************************************************************************************

//입력창에서 사용
void GotoXY(int x, int y) {
	COORD pos = { x,y };
	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), pos);
}

//Hex to Binary 함수. 32자리의 char 형태의 HASH 값을 256자리의 0과 1로 이루어진 문자열로 전환한다.
void H_to_B(char HexStr[], char BinaryStr[]) {
	unsigned char n;
	for (int i = 0; i < 32; i++) {
		n = *(HexStr + i);
		for (int j = 0; n > 0; j++)
		{
			BinaryStr[i * 8 + 7 - j] = n % 2; //유클리드 호제법 사용
			n = n / 2;
		}
	}
}

//파일 암호화 함수. 성공하면 1, 실패하면 0을 반환한다.
int FileEncrypt(char FileName[], char EncryptKey[]) {
	char* EncryptContent = { 0 };							//파일의 내용물을 담을 배열이다.
	int EncryptValue;										//파일 암호화의 증감값을 정해주는 값으로, 암호화 키의 첫 문자의 아스키코드를 사용한다.
	char NewFileName[200] = { 0 }, Extention[100] = { 0 };	//변경될 파일이름과 변경될 확장자의 문자열이다.
	EncryptValue = EncryptKey[0];

	//파일의 확장자(.) 위치를 파악한다.
	char* DotPointer = strchr(FileName, '.');
	if (DotPointer == NULL)
		return 0;
	int DotLocation = strlen(FileName) - strlen(DotPointer);

	//파일의 확장자를 제거하고 지정된 확장자(Signature) 으로 변경한다. 제거된 확장자는 암호화된 파일 내부에 기록된다.
	for (int i = 0; i < DotLocation; i++)
		NewFileName[i] = FileName[i];
	for (int i = DotLocation + 1; i < strlen(FileName); i++)
		Extention[i - DotLocation - 1] = FileName[i];
	NewFileName[DotLocation] = '.';
	for (int i = 0; i <= strlen(Signature); i++) {
		NewFileName[i + DotLocation + 1] = Signature[i];
	}

	//파일을 연다.
	int FileSize;								//파일의 크기를 측정하는 변수로, EncryptContent가 할당할 메모리의 양을 결정한다.
	FILE* EncryptTargetFile;					//파일 변수
	EncryptTargetFile = fopen(FileName, "rb");	//파일을 읽기 형식으로 연다.
	if (EncryptTargetFile == NULL)
		return 0;								//파일이 존재하지 않는다면 0을 반환한다.

	//파일의 크기를 측정하여 EncryptContent의 메모리를 할당한다.
	fseek(EncryptTargetFile, 0, SEEK_END);		//파일 크기를 측정한다.
	FileSize = ftell(EncryptTargetFile);
	fseek(EncryptTargetFile, 0, SEEK_SET);
	if (FileSize > MAXSIZE)						//파일이 일정 크기 이상으로 크다면 특정 부분만 암호화시킨다.
		FileSize = MAXSIZE;
	EncryptContent = (char*)malloc(sizeof(char) * (FileSize + strlen(Extention) + 2));	//EncryptContent에 메모리를 할당한다.
	if (EncryptContent == NULL)
		return 0;								//메모리 할당에 실패했다면 0을 반환한다.

	//파일의 내용을 EncryptContent 변수에 저장한 후, 암호화한다.
	fread(EncryptContent, sizeof(char), FileSize, EncryptTargetFile);	//파일을 읽어 EncryptContent에 저장한다.
	fclose(EncryptTargetFile);											//파일을 닫는다.
	char HexKey[SHA256_BLOCK_SIZE] = { 0 };
	char BinaryKey[256];
	SHA256(EncryptKey, HexKey);											//암호화 키의 HASH 값을 8비트 char 32개로 받는다.
	H_to_B(HexKey, BinaryKey);											//받은 HASH 값을 256개의 1과 0으로 변환한다.
	//파일 암호화
	for (int i = 0; i < FileSize; i++) {
		if (BinaryKey[i % 256] == '1')									//HASH 값이 1이라면 더하고, 0이라면 뺀다. (카이사르 암호 원리)
			EncryptContent[i] += EncryptValue;
		else
			EncryptContent[i] -= EncryptValue;
	}
	int j = 0;
	//EncryptContent에 제거된 확장자를 집어넣는다.
	for (int i = FileSize; i < FileSize + strlen(Extention); i++) {
		EncryptContent[i] = Extention[j];
		j++;
	}
	 
	//EncryptContent의 내용물을 다시 파일 안에 집어넣는다.
	EncryptContent[FileSize + strlen(Extention)] = strlen(Extention);
	EncryptContent[FileSize + strlen(Extention) + 1] = NULL;
	EncryptTargetFile = fopen(FileName, "wb");	//파일을 쓰기 형식으로 연다.
	if (EncryptTargetFile == NULL) 
		return 0;								//파일을 열 수 없다면 0을 반환한다.
	fwrite(EncryptContent, sizeof(char), FileSize + strlen(Extention) + 1, EncryptTargetFile);	//EncryptContent의 내용물을 파일 안에 집어넣는다.
	fclose(EncryptTargetFile);					//파일을 닫는다.
	free(EncryptContent);						//동적 할당된 메모리를 푼다.
	rename(FileName, NewFileName);				//기존 파일의 이름을 확장자가 제거된 파일 이름으로 바꾼다.
	return 1;	//1을 반환한다.
}

//파일 복호화 함수. 성공하면 1, 실패하면 0을 반환한다. 원리는 FileEncrypt 함수와 같다.
int FileDecrypt(char FileName[], char DecryptKey[]) {
	char* DecryptContent = { 0 };
	int DecryptValue;
	char NewFileName[200] = { 0 }, Extention[100] = { 0 };
	DecryptValue = DecryptKey[0];
	char* DotPointer = strchr(FileName, '.');
	if (DotPointer == NULL)
		return 0;
	int DotLocation = strlen(FileName) - strlen(DotPointer);
	for (int i = 0; i < DotLocation; i++)
		NewFileName[i] = FileName[i];
	int FileSize;
	FILE* DecryptTargetFile;
	DecryptTargetFile = fopen(FileName, "rb");
	if (DecryptTargetFile == NULL)
		return 0;
	fseek(DecryptTargetFile, 0, SEEK_END);
	FileSize = ftell(DecryptTargetFile);
	fseek(DecryptTargetFile, 0, SEEK_SET);
	if (FileSize > MAXSIZE)
		FileSize = MAXSIZE;
	DecryptContent = (char*)malloc(sizeof(char) * (FileSize));
	if (DecryptContent == NULL)
		return 0;
	fread(DecryptContent, sizeof(char), FileSize, DecryptTargetFile);
	fclose(DecryptTargetFile);
	char ExtentionSize = DecryptContent[FileSize - 1];
	DecryptContent[FileSize - 1] = NULL;
	char HexKey[SHA256_BLOCK_SIZE] = { 0 };
	char BinaryKey[256];
	SHA256(DecryptKey, HexKey);
	H_to_B(HexKey, BinaryKey);
	for (int i = 0; i < FileSize - ExtentionSize - 1; i++) {
		if (BinaryKey[i % 256] == '1')
			DecryptContent[i] -= DecryptValue;
		else
			DecryptContent[i] += DecryptValue;
	}
	for (int i = FileSize - ExtentionSize - 1; i < FileSize - 1; i++) {
		Extention[i - FileSize + ExtentionSize + 1] = DecryptContent[i];
		DecryptContent[i] = NULL;
	}
	NewFileName[DotLocation] = '.';
	for (int i = 0; i <= strlen(Extention); i++) {
		NewFileName[i + DotLocation + 1] = Extention[i];
	}
	DecryptTargetFile = fopen(FileName, "wb");
	if (DecryptTargetFile == NULL) 
		return 0;
	fwrite(DecryptContent, sizeof(char), FileSize - ExtentionSize - 1, DecryptTargetFile);
	fclose(DecryptTargetFile);
	free(DecryptContent);
	rename(FileName, NewFileName);
	return 1;
}


//디렉토리 탐색 함수. 지정된 디렉토리의 모든 파일을 탐색하여 FileEncrypt 함수를 호출시킨다.
void FolderEncrypt(char FolderLocation[], char EncryptKey[]) {

	//파일 탐색 준비
	char Path[500], FileName[200], FilePath[500], tmp[1000];
	/*
	* Path : 탐색할 디렉토리의 주소이다.
	* FileName : 현재 탐색중인 파일 또는 디렉토리의 이름이다.
	* FilePath : 현재 탐색중인 파일 또는 디렉토리의 주소이다.
	* tmp : 임시 문자열 변수이다.
	*/

	strcpy(Path, FolderLocation);
	strcat(Path, "*.*");			//탐색할 디렉토리의 이름을 문자열로 구성한다.

	struct _finddata_t FileSearch;	//파일 탐색 구조체이다.
	intptr_t Handle;
	if ((Handle = _findfirst(Path, &FileSearch)) == -1L) {	//디렉토리를 찾을 수 없다면 함수를 종료한다.
		printf("디렉토리를 찾을 수 없습니다\n");
		return;
	}
	int IsSuccess;	//파일 암호화의 성공 여부를 알려주는 변수. 성공하면 1, 실패하면 0 이다.

	//파일 탐색 알고리즘
	while (1)
	{
		strcpy(FileName, FileSearch.name);				//탐색된 파일의 이름을 FileName 문자열에 저장한다.
		if (strchr(FileName, '.') == NULL) {			//탐색된 파일에 .이 존재하지 않는다면, 디렉토리로 간주하고 자기 자신을 호출해 해당 디렉토리를 조사한다.
			strcpy(tmp, FolderLocation);
			strcat(tmp, FileName);
			strcat(tmp, "\\");
			FolderEncrypt(tmp, EncryptKey);
		}
		strcpy(FilePath, FolderLocation);
		strcat(FilePath, FileSearch.name);				//탐색된 파일 이름에 탐색할 디렉토리의 주소를 붙여 탐색된 파일의 주소를 구성한다.
		IsSuccess = FileEncrypt(FilePath, EncryptKey);	//탐색된 파일 주소를 FileEncrypt 함수에 넘겨 해당 파일을 암호화시킨다.
		if (IsSuccess)
			printf("%d번째 파일 ( %s ) : 성공\n", KeyDepth, FileSearch.name); //암호화에 성공했다면 성공을 출력한다.
		else
			printf("%d번째 파일 ( %s ) : 실패\n", KeyDepth, FileSearch.name);	 //암호화에 실패했다면 실패를 출력한다.
		KeyDepth++;										//탐색중인 파일의 번호
		if (_findnext(Handle, &FileSearch) != 0)		//다음으로 탐색할 파일이 존재하지 않는다면 while 문에서 탈출한다.
			break;
	}
	_findclose(Handle);
	return;	//함수 종료
}

//디렉토리 탐색 함수. 지정된 디렉토리의 모든 파일을 탐색하여 FileDecrypt 함수를 호출시킨다. 원리는 FolderDecrypt 함수와 같다.
void FolderDecrypt(char FileLocation[], char DecryptKey[]) {
	char Path[500], FileName[200], FilePath[500], tmp[1000];
	strcpy(Path, FileLocation);
	strcat(Path, "*.*");
	struct _finddata_t FileSearch;
	intptr_t Handle;
	if ((Handle = _findfirst(Path, &FileSearch)) == -1L) {
		printf("디렉토리를 찾을 수 없습니다\n");
		return;
	}
	_Bool success;
	while (1)
	{
		strcpy(FileName, FileSearch.name);
		if (strchr(FileName, '.') == NULL) {
			strcpy(tmp, FileLocation);
			strcat(tmp, FileName);
			strcat(tmp, "\\");
			FolderDecrypt(tmp, DecryptKey);
		}
		strcpy(FilePath, FileLocation);
		strcat(FilePath, FileSearch.name);
		success = FileDecrypt(FilePath, DecryptKey);
		if (success)
			printf("%d번째 파일 ( %s ) : 성공\n", KeyDepth, FileSearch.name);
		else
			printf("%d번째 파일 ( %s ) : 실패\n", KeyDepth, FileSearch.name);
		KeyDepth++;
		if (_findnext(Handle, &FileSearch) != 0)
			break;
	}
	_findclose(Handle);
	return;
}

int main() {
	printf("암호화와 복호화 작업중 어느 작업을 선택하시겠습니까?\n\n암호화 <\n복호화 ");
	GotoXY(8, 2);
	int Select = 1;
	while (1) {
		char KeyInput = getch();
		if (KeyInput == 80 && Select) {
			GotoXY(7, 2);
			printf("\b  ");
			GotoXY(7, 3);
			printf("<");
			Select = 0;
		}
		else if (KeyInput == 72 && !Select) {
			GotoXY(7, 3);
			printf("\b  ");
			GotoXY(7, 2);
			printf("<");
			Select = 1;
		}
		else if (KeyInput == 13) {
			system("cls");
			if (Select) {
				char FileLocation[500], EncryptKey[100];
				printf("암호화할 폴더 경로를 입력하세요 : ");
				scanf(" %[^\n]", FileLocation);	//엔터키가 입력될때까지 문자 입력
				if (FileLocation[strlen(FileLocation) - 1] != '\\')
					strcat(FileLocation,"\\");
				printf("암호화 키를 입력하세요 : ");
				scanf(" %[^\n]", EncryptKey);	//엔터키가 입력될때까지 문자 입력
				FolderEncrypt(FileLocation, EncryptKey); //디렉토리 탐색 함수 호출
				break;
			}
			else {
				char FileLocation[500], DecryptKey[100];
				printf("복호화할 폴더 경로를 입력하세요 : ");
				scanf(" %[^\n]", FileLocation);	//엔터키가 입력될때까지 문자 입력
				if (FileLocation[strlen(FileLocation) - 1] != '\\')
					strcat(FileLocation, "\\");
				printf("복호화 키를 입력하세요 : ");
				scanf(" %[^\n]", DecryptKey);	//엔터키가 입력될때까지 문자 입력
				FolderDecrypt(FileLocation, DecryptKey); //디렉토리 탐색 함수 호출
				break;
			}
		}
	}
	printf("\n아무 키나 눌러 종료하십시오...");
	getch();
	return 0;
}