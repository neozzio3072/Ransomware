#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <conio.h>
#include <io.h>
#pragma warning(disable:4996)

//***************************************************************************************************************
//SHA-256 �ڵ�
//SHA-256 �ڵ�� �л� ������ �ۼ����� ����.
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

//SHA-256 ���� �Լ�
void SHA256(unsigned char string[], unsigned char hash[]) {
	SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, string, strlen(string));
	sha256_final(&ctx, hash);
}
//***************************************************************************************************************

//�Է�â���� ���
void GotoXY(int x, int y) {
	COORD pos = { x,y };
	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), pos);
}

//Hex to Binary �Լ�. 32�ڸ��� char ������ HASH ���� 256�ڸ��� 0�� 1�� �̷���� ���ڿ��� ��ȯ�Ѵ�.
void H_to_B(char HexStr[], char BinaryStr[]) {
	unsigned char n;
	for (int i = 0; i < 32; i++) {
		n = *(HexStr + i);
		for (int j = 0; n > 0; j++)
		{
			BinaryStr[i * 8 + 7 - j] = n % 2; //��Ŭ���� ȣ���� ���
			n = n / 2;
		}
	}
}

//���� ��ȣȭ �Լ�. �����ϸ� 1, �����ϸ� 0�� ��ȯ�Ѵ�.
int FileEncrypt(char FileName[], char EncryptKey[]) {
	char* EncryptContent = { 0 };							//������ ���빰�� ���� �迭�̴�.
	int EncryptValue;										//���� ��ȣȭ�� �������� �����ִ� ������, ��ȣȭ Ű�� ù ������ �ƽ�Ű�ڵ带 ����Ѵ�.
	char NewFileName[200] = { 0 }, Extention[100] = { 0 };	//����� �����̸��� ����� Ȯ������ ���ڿ��̴�.
	EncryptValue = EncryptKey[0];

	//������ Ȯ����(.) ��ġ�� �ľ��Ѵ�.
	char* DotPointer = strchr(FileName, '.');
	if (DotPointer == NULL)
		return 0;
	int DotLocation = strlen(FileName) - strlen(DotPointer);

	//������ Ȯ���ڸ� �����ϰ� ������ Ȯ����(Signature) ���� �����Ѵ�. ���ŵ� Ȯ���ڴ� ��ȣȭ�� ���� ���ο� ��ϵȴ�.
	for (int i = 0; i < DotLocation; i++)
		NewFileName[i] = FileName[i];
	for (int i = DotLocation + 1; i < strlen(FileName); i++)
		Extention[i - DotLocation - 1] = FileName[i];
	NewFileName[DotLocation] = '.';
	for (int i = 0; i <= strlen(Signature); i++) {
		NewFileName[i + DotLocation + 1] = Signature[i];
	}

	//������ ����.
	int FileSize;								//������ ũ�⸦ �����ϴ� ������, EncryptContent�� �Ҵ��� �޸��� ���� �����Ѵ�.
	FILE* EncryptTargetFile;					//���� ����
	EncryptTargetFile = fopen(FileName, "rb");	//������ �б� �������� ����.
	if (EncryptTargetFile == NULL)
		return 0;								//������ �������� �ʴ´ٸ� 0�� ��ȯ�Ѵ�.

	//������ ũ�⸦ �����Ͽ� EncryptContent�� �޸𸮸� �Ҵ��Ѵ�.
	fseek(EncryptTargetFile, 0, SEEK_END);		//���� ũ�⸦ �����Ѵ�.
	FileSize = ftell(EncryptTargetFile);
	fseek(EncryptTargetFile, 0, SEEK_SET);
	if (FileSize > MAXSIZE)						//������ ���� ũ�� �̻����� ũ�ٸ� Ư�� �κи� ��ȣȭ��Ų��.
		FileSize = MAXSIZE;
	EncryptContent = (char*)malloc(sizeof(char) * (FileSize + strlen(Extention) + 2));	//EncryptContent�� �޸𸮸� �Ҵ��Ѵ�.
	if (EncryptContent == NULL)
		return 0;								//�޸� �Ҵ翡 �����ߴٸ� 0�� ��ȯ�Ѵ�.

	//������ ������ EncryptContent ������ ������ ��, ��ȣȭ�Ѵ�.
	fread(EncryptContent, sizeof(char), FileSize, EncryptTargetFile);	//������ �о� EncryptContent�� �����Ѵ�.
	fclose(EncryptTargetFile);											//������ �ݴ´�.
	char HexKey[SHA256_BLOCK_SIZE] = { 0 };
	char BinaryKey[256];
	SHA256(EncryptKey, HexKey);											//��ȣȭ Ű�� HASH ���� 8��Ʈ char 32���� �޴´�.
	H_to_B(HexKey, BinaryKey);											//���� HASH ���� 256���� 1�� 0���� ��ȯ�Ѵ�.
	//���� ��ȣȭ
	for (int i = 0; i < FileSize; i++) {
		if (BinaryKey[i % 256] == '1')									//HASH ���� 1�̶�� ���ϰ�, 0�̶�� ����. (ī�̻縣 ��ȣ ����)
			EncryptContent[i] += EncryptValue;
		else
			EncryptContent[i] -= EncryptValue;
	}
	int j = 0;
	//EncryptContent�� ���ŵ� Ȯ���ڸ� ����ִ´�.
	for (int i = FileSize; i < FileSize + strlen(Extention); i++) {
		EncryptContent[i] = Extention[j];
		j++;
	}
	 
	//EncryptContent�� ���빰�� �ٽ� ���� �ȿ� ����ִ´�.
	EncryptContent[FileSize + strlen(Extention)] = strlen(Extention);
	EncryptContent[FileSize + strlen(Extention) + 1] = NULL;
	EncryptTargetFile = fopen(FileName, "wb");	//������ ���� �������� ����.
	if (EncryptTargetFile == NULL) 
		return 0;								//������ �� �� ���ٸ� 0�� ��ȯ�Ѵ�.
	fwrite(EncryptContent, sizeof(char), FileSize + strlen(Extention) + 1, EncryptTargetFile);	//EncryptContent�� ���빰�� ���� �ȿ� ����ִ´�.
	fclose(EncryptTargetFile);					//������ �ݴ´�.
	free(EncryptContent);						//���� �Ҵ�� �޸𸮸� Ǭ��.
	rename(FileName, NewFileName);				//���� ������ �̸��� Ȯ���ڰ� ���ŵ� ���� �̸����� �ٲ۴�.
	return 1;	//1�� ��ȯ�Ѵ�.
}

//���� ��ȣȭ �Լ�. �����ϸ� 1, �����ϸ� 0�� ��ȯ�Ѵ�. ������ FileEncrypt �Լ��� ����.
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


//���丮 Ž�� �Լ�. ������ ���丮�� ��� ������ Ž���Ͽ� FileEncrypt �Լ��� ȣ���Ų��.
void FolderEncrypt(char FolderLocation[], char EncryptKey[]) {

	//���� Ž�� �غ�
	char Path[500], FileName[200], FilePath[500], tmp[1000];
	/*
	* Path : Ž���� ���丮�� �ּ��̴�.
	* FileName : ���� Ž������ ���� �Ǵ� ���丮�� �̸��̴�.
	* FilePath : ���� Ž������ ���� �Ǵ� ���丮�� �ּ��̴�.
	* tmp : �ӽ� ���ڿ� �����̴�.
	*/

	strcpy(Path, FolderLocation);
	strcat(Path, "*.*");			//Ž���� ���丮�� �̸��� ���ڿ��� �����Ѵ�.

	struct _finddata_t FileSearch;	//���� Ž�� ����ü�̴�.
	intptr_t Handle;
	if ((Handle = _findfirst(Path, &FileSearch)) == -1L) {	//���丮�� ã�� �� ���ٸ� �Լ��� �����Ѵ�.
		printf("���丮�� ã�� �� �����ϴ�\n");
		return;
	}
	int IsSuccess;	//���� ��ȣȭ�� ���� ���θ� �˷��ִ� ����. �����ϸ� 1, �����ϸ� 0 �̴�.

	//���� Ž�� �˰���
	while (1)
	{
		strcpy(FileName, FileSearch.name);				//Ž���� ������ �̸��� FileName ���ڿ��� �����Ѵ�.
		if (strchr(FileName, '.') == NULL) {			//Ž���� ���Ͽ� .�� �������� �ʴ´ٸ�, ���丮�� �����ϰ� �ڱ� �ڽ��� ȣ���� �ش� ���丮�� �����Ѵ�.
			strcpy(tmp, FolderLocation);
			strcat(tmp, FileName);
			strcat(tmp, "\\");
			FolderEncrypt(tmp, EncryptKey);
		}
		strcpy(FilePath, FolderLocation);
		strcat(FilePath, FileSearch.name);				//Ž���� ���� �̸��� Ž���� ���丮�� �ּҸ� �ٿ� Ž���� ������ �ּҸ� �����Ѵ�.
		IsSuccess = FileEncrypt(FilePath, EncryptKey);	//Ž���� ���� �ּҸ� FileEncrypt �Լ��� �Ѱ� �ش� ������ ��ȣȭ��Ų��.
		if (IsSuccess)
			printf("%d��° ���� ( %s ) : ����\n", KeyDepth, FileSearch.name); //��ȣȭ�� �����ߴٸ� ������ ����Ѵ�.
		else
			printf("%d��° ���� ( %s ) : ����\n", KeyDepth, FileSearch.name);	 //��ȣȭ�� �����ߴٸ� ���и� ����Ѵ�.
		KeyDepth++;										//Ž������ ������ ��ȣ
		if (_findnext(Handle, &FileSearch) != 0)		//�������� Ž���� ������ �������� �ʴ´ٸ� while ������ Ż���Ѵ�.
			break;
	}
	_findclose(Handle);
	return;	//�Լ� ����
}

//���丮 Ž�� �Լ�. ������ ���丮�� ��� ������ Ž���Ͽ� FileDecrypt �Լ��� ȣ���Ų��. ������ FolderDecrypt �Լ��� ����.
void FolderDecrypt(char FileLocation[], char DecryptKey[]) {
	char Path[500], FileName[200], FilePath[500], tmp[1000];
	strcpy(Path, FileLocation);
	strcat(Path, "*.*");
	struct _finddata_t FileSearch;
	intptr_t Handle;
	if ((Handle = _findfirst(Path, &FileSearch)) == -1L) {
		printf("���丮�� ã�� �� �����ϴ�\n");
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
			printf("%d��° ���� ( %s ) : ����\n", KeyDepth, FileSearch.name);
		else
			printf("%d��° ���� ( %s ) : ����\n", KeyDepth, FileSearch.name);
		KeyDepth++;
		if (_findnext(Handle, &FileSearch) != 0)
			break;
	}
	_findclose(Handle);
	return;
}

int main() {
	printf("��ȣȭ�� ��ȣȭ �۾��� ��� �۾��� �����Ͻðڽ��ϱ�?\n\n��ȣȭ <\n��ȣȭ ");
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
				printf("��ȣȭ�� ���� ��θ� �Է��ϼ��� : ");
				scanf(" %[^\n]", FileLocation);	//����Ű�� �Էµɶ����� ���� �Է�
				if (FileLocation[strlen(FileLocation) - 1] != '\\')
					strcat(FileLocation,"\\");
				printf("��ȣȭ Ű�� �Է��ϼ��� : ");
				scanf(" %[^\n]", EncryptKey);	//����Ű�� �Էµɶ����� ���� �Է�
				FolderEncrypt(FileLocation, EncryptKey); //���丮 Ž�� �Լ� ȣ��
				break;
			}
			else {
				char FileLocation[500], DecryptKey[100];
				printf("��ȣȭ�� ���� ��θ� �Է��ϼ��� : ");
				scanf(" %[^\n]", FileLocation);	//����Ű�� �Էµɶ����� ���� �Է�
				if (FileLocation[strlen(FileLocation) - 1] != '\\')
					strcat(FileLocation, "\\");
				printf("��ȣȭ Ű�� �Է��ϼ��� : ");
				scanf(" %[^\n]", DecryptKey);	//����Ű�� �Էµɶ����� ���� �Է�
				FolderDecrypt(FileLocation, DecryptKey); //���丮 Ž�� �Լ� ȣ��
				break;
			}
		}
	}
	printf("\n�ƹ� Ű�� ���� �����Ͻʽÿ�...");
	getch();
	return 0;
}