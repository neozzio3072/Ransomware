#include <stdio.h>
#include <conio.h>
#pragma warning(disable:4996)

int duplicate() {
	int size;
	char* DNA = { 0 };
	FILE* dupl1;
	dupl1 = fopen("Duplicate.exe", "rb");
	if (dupl1 == NULL)
		return 0;
	fseek(dupl1, 0, SEEK_END);
	size = ftell(dupl1);
	fseek(dupl1, 0, SEEK_SET);
	DNA = (char*)malloc(sizeof(char) * (size));
	fread(DNA, sizeof(char), size, dupl1);
	fclose(dupl1);
	FILE* dupl2;
	dupl2 = fopen("DuplicateDNA", "w+");
	fclose(dupl2);
	FILE* dupl3;
	dupl3 = fopen("DuplicateDNA", "wb");
	if (dupl3 == NULL)
		return 0;
	fwrite(DNA, sizeof(char), size, dupl3);
	fclose(dupl3);
	free(DNA);
	rename("DuplicateDNA", "Duplicate.exe");
	return 1;
}

int main() {
	if (duplicate()) 
		printf("I Duplicate Myself");
	else
		printf("Nevermind");
	char a = getch();
}