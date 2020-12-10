/*
  * Block Cipher - AES voi MDS 4x4 theo bang nhan tren truong
  * thohd 2018
  * edit: tungpv
  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <io.h>
#include <dos.h>
#include <time.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <streambuf>
//#include "FMuls.h"
using namespace std;

int Nk = 8;
int Nr = 14;
unsigned char *key;
unsigned char invSBox[16 * 16];
unsigned char state[4 * 4];        /* 128 bit */
unsigned char w[4 * (14 + 1) * 4]; /* max */

unsigned char Sbox[16 * 16] = { // populate the Sbox matrix
                                /* 0 1 2 3 4 5 6 7 8 9 a b c
   d e f */
    /*0*/ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    /*1*/ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    /*2*/ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    /*3*/ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    /*4*/ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    /*5*/ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    /*6*/ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    /*7*/ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    /*8*/ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    /*9*/ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    /*a*/ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    /*b*/ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    /*c*/ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    /*d*/ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    /*e*/ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    /*f*/ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

unsigned char Rcon[11 * 4] = {0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
                              0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x10, 0x00,
                              0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x80,
                              0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00};

// Phep nhan tren truong GF(2^8)
/* Thuc hien phep nhan 0x02 * a */

unsigned char gfMultBy02(unsigned char i)
{
  if (i < 0x80)
    i = i << 1;
  else
  {
    i = i << 1;
    i = (unsigned char)((int)i ^ (int)0x1b);
    // i=(unsigned char)((int)i^(int)0x1b);
    // i=i<<1;
  }
  return i;
}

/* Thuc hien phep nhan 0x03 * a */
unsigned char gfMultBy03(unsigned char i)
{
  return (unsigned char)((int)gfMultBy02(i) ^ (int)i);
}

/* Thuc hien phep nhan
  * 0x09 * a = (a * 0x02 * 0x02 * 0x02 ) + (a * 0x01)
  * - dung khi giai ma
  */
unsigned char gfMultBy09(unsigned char i)
{
  return (unsigned char)((int)gfMultBy02(gfMultBy02(gfMultBy02(i))) ^ (int)i);
}

/* Thuc hien phep nhan 0x0b * a
  * 0x0b * a = (a * 0x02 * 0x02 * 0x02 ) + (a * 0x02) + (a * 0x01)
  * - dung khi giai ma
  */
unsigned char gfMultBy0b(unsigned char i)
{
  return (unsigned char)((int)gfMultBy02(gfMultBy02(gfMultBy02(i))) ^ (int)gfMultBy02(i) ^ (int)i);
}

/* Thuc hien phep nhan 0x0d * a
 * 0x0d * a = (a * 0x02 * 0x02 * 0x02 ) + (a * 0x02 * 0x02 ) + (a * 0x01)
 - dung khi giai ma*/
unsigned char gfMultBy0d(unsigned char i)
{
  return (unsigned char)((int)gfMultBy02(gfMultBy02(gfMultBy02(i))) ^
                         (int)gfMultBy02(gfMultBy02(i)) ^ (int)(i));
}

/* Thuc hien phep nhan 0x0e * a
 * 0x0e * a = (a * 0x02 * 0x02 * 0x02 ) + (a * 0x02 * 0x02 ) + (a * 0x02)
 - dung khi giai ma*/
unsigned char gfMultBy0e(unsigned char i)
{
  return (unsigned char)((int)gfMultBy02(gfMultBy02(gfMultBy02(i))) ^
                         (int)gfMultBy02(gfMultBy02(i)) ^ (int)gfMultBy02(i));
}
/* numkey = 0, 1, 2 */
void SetNkNr(int numkey)
{

  if ((numkey == 0) || (numkey == 128))
  {
    Nk = 4;
    Nr = 10;
  }
  else if ((numkey == 1) || (numkey == 192))
  {
    Nk = 6;
    Nr = 12;
  }
  else if ((numkey == 2) || (numkey == 256))
  {
    Nk = 8;
    Nr = 14;
  }

  /* DEBUG */
  printf("\n Nk = %d ", Nk);
  printf("\n Nr = %d ", Nr);
}

/* Tao hop the nguoc voi Sbox - dung khi giai ma */
void InitInvSBox(void)
{
  FILE *f;

  for (int i = 0; i < 16; i++)
    for (int j = 0; j < 16; j++)
    {
      unsigned char t;
      int x, y;
      t = Sbox[i * 16 + j];
      x = ((unsigned char)((int)(t) >> 4));
      y = ((unsigned char)((int)(t)&0x0f));
      invSBox[x * 16 + y] = (unsigned char)((i << 4) + j);
    }

  f = fopen("invSbox.txt", "wb");
  fprintf(f, "\n Hop the hoan vi nguoc: ");
  fprintf(f, "\n invSBox[16*16] = {\n");

  for (int i = 0; i < 16; i++)
  {
    for (int j = 0; j < 16; j++)
    {
      fprintf(f, "%02X, ", invSBox[i * 16 + j]);
    }
    fprintf(f, "\n");
  }
  fprintf(f, "};");

  fclose(f);
}

// Dich vong trai di 1 Byte
unsigned long RotWord(unsigned long t)
{
  unsigned char *p;
  unsigned char temp;

  p = (unsigned char *)&t;
  temp = *p;
  *p = *(p + 1);
  p++;
  *p = *(p + 1);
  p++;
  *p = *(p + 1);
  p++;
  *p = temp;

  return t;
}

// Dich trai cac dong (hang)
void ShiftRows(void)
{
  unsigned char temp[4 * 4];
  for (int i = 1; i < 4; i++)
    for (int j = 0; j < 4; j++)
    {
      temp[i * 4 + j] = state[i * 4 + j];
    }

  /* Vi dong 0 khong dich vong. Dong thu i dich di i byte */
  for (int i = 1; i < 4; i++)
    for (int j = 0; j < 4; j++)
    {
      state[i * 4 + j] = temp[i * 4 + ((i + j) % 4)];
    }
}

// Thay the mang 4*4 State thanh mang 4*4 qua Sbox.
void SubBytes(void)
{
  int x, y;
  for (int i = 0; i < 4; i++)   /* cot */
    for (int j = 0; j < 4; j++) /* hang */
    {
      /* a[i, j] = Sbox[a[i,j]] */
      // x= (unsigned char)((int)(state[i*4+j])>>4);
      // y= (unsigned char)((int)(state[i*4+j])& 0x0f);
      state[i * 4 + j] = Sbox[state[i * 4 + j]];
    }
}

// Thay the qua Sbox. Thay the 4 byte. Dung trong luoc do tao khoa.
unsigned long SubWord(unsigned long t)
{
  unsigned char *p;
  int x, y;

  p = (unsigned char *)&t;
  x = (unsigned char)((int)(*p) >> 4);
  y = (unsigned char)((int)(*p) & 0x0f);
  *p = Sbox[x * 16 + y];

  p++;
  x = (unsigned char)((int)(*p) >> 4);
  y = (unsigned char)((int)(*p) & 0x0f);
  *p = Sbox[x * 16 + y];

  p++;
  x = (unsigned char)((int)(*p) >> 4);
  y = (unsigned char)((int)(*p) & 0x0f);
  *p = Sbox[x * 16 + y];

  p++;
  x = (unsigned char)((int)(*p) >> 4);
  y = (unsigned char)((int)(*p) & 0x0f);
  *p = Sbox[x * 16 + y];
  return t;
}

/* Expantion userkey to Key Schedule */
/*
 Mo rong tu 128 -> 4*(10+1)*4 = 1408 bit khoa con - 10 vong.
 Mo rong tu 192 -> 4*(12+1)*4 = 1664 bit khoa con - 12 vong.
 Mo rong tu 256 -> 4*(14+1)*4 = 2000 bit khoa con - 14 vong.

 Vi moi vong su dung Nb = 4*4 byte khoa. Can them 1 khoa con cho
 vong cuoi cung.
 */
void KeyExpantion(unsigned char *key, unsigned char *w)
{
  /* Nk*4 byte dau duoc lay tu khoa vao -> duoc Nk dong */
  for (int i = 0; i < Nk; i++)
  {
    /* theo dong */
    w[i * 4] = key[i * 4];
    w[i * 4 + 1] = key[i * 4 + 1];
    w[i * 4 + 2] = key[i * 4 + 2];
    w[i * 4 + 3] = key[i * 4 + 3];
  }

  /* Tu dong thu Nk den 4*(Nr+1)*4 */
  for (int row = Nk; row < (4 * (Nr + 1)); row++)
  {
    unsigned long temp = *((unsigned long *)&w[(row - 1) * 4]); /* W[i-1] = w[4*(i-1)]*/

    if (row % Nk == 0)
    {
      temp = SubWord(RotWord(temp)) ^ (*((unsigned long *)&Rcon[(row / Nk) * 11]));
    }
    else if (Nk > 6 && (row % Nk == 4))
    {
      temp = SubWord(temp);
    }
    temp = temp ^ (*((unsigned long *)(&w[(row - Nk) * 4])));

    /* Ghi lai 4 byte nay vao w ung voi dong khoa thu row*/
    *((unsigned long *)&w[row * 4]) = temp;
  }
}

/* Cong State voi khoa vong thu round */
void AddRoundKey(int round)
{
  for (int i = 0; i < 4; i++)   /* cot */
    for (int j = 0; j < 4; j++) /* hang */
    {
      state[i * 4 + j] = (unsigned char)((int)state[i * 4 + j] ^ (int)w[(round * 4 + j) * 4 + i]);
    }
}

/* MixColumns */
void MixColumns(void)
{
  unsigned char temp[4 * 4];

  /* Copy du lieu tu State vao temp */
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
    {
      temp[i * 4 + j] = state[i * 4 + j];
    }

  //Ma tran goc === cot 1 va 2
  for (int i = 0; i < 4; i++)
  {
    state[0 * 4 + i] = (unsigned char)((int)gfMultBy02(temp[0 * 4 + i]) ^
                                       (int)gfMultBy03(temp[1 * 4 + i]) ^
                                       (int)temp[2 * 4 + i] ^
                                       (int)temp[3 * 4 + i]);

    state[1 * 4 + i] = (unsigned char)((int)temp[0 * 4 + i] ^
                                       (int)gfMultBy02(temp[1 * 4 + i]) ^
                                       (int)gfMultBy03(temp[2 * 4 + i]) ^
                                       (int)temp[3 * 4 + i]);

    state[2 * 4 + i] = (unsigned char)((int)temp[0 * 4 + i] ^
                                       (int)temp[1 * 4 + i] ^
                                       (int)gfMultBy02(temp[2 * 4 + i]) ^
                                       (int)gfMultBy03(temp[3 * 4 + i]));

    state[3 * 4 + i] = (unsigned char)((int)gfMultBy03(temp[0 * 4 + i]) ^
                                       (int)temp[1 * 4 + i] ^
                                       (int)temp[2 * 4 + i] ^
                                       (int)gfMultBy02(temp[3 * 4 + i]));
  }
}

void AES_Cipher(unsigned char *input, unsigned char *output)
{
  /* 0. Neu khong co du lieu vao -> THOAT */
  if ((input == NULL) || (output == NULL))
    return;

  /* 1. Dua input vao State */
  for (int i = 0; i < 16; i++)
  {
    /* theo cot truoc */
    state[(i % 4) * 4 + (i / 4)] = input[i];
  }

  /* 2. AddRoundKey - vong thu 0*/
  // printf("\n round [0]. input ");
  //for (int i=0; i<16; i++) printf("%02X", state[(i%4)*4 + (i/4)]);
  AddRoundKey(0);
  //printf("\n round [0]. k_sch ");
  //for (int i=0; i<16; i++) printf("%02X", w[i]);

  /* 3. Thuc hien Nr vong lap */
  for (int round = 1; round <= (Nr - 1); ++round)
  {
    // printf("\n round [%d]. start ", round);
    //for (int i=0; i<16; i++) printf("%02X", state[(i%4)*4 + (i/4)]);

    SubBytes();

    //printf("\n round [%d]. s_box ", round);
    //for (int i=0; i<16; i++) printf("%02X", state[(i%4)*4 + (i/4)]);

    ShiftRows();

    //printf("\n round [%d]. s_row ", round);
    //for (int i=0; i<16; i++) printf("%02X", state[(i%4)*4 + (i/4)]);

    MixColumns();

    //printf("\n round [%d]. m_col ", round);
    //for (int i=0; i<16; i++) printf("%02X", state[(i%4)*4 + (i/4)]);

    AddRoundKey(round);

    //printf("\n round [%d]. k_sch ", round);
    //for (int i=0; i<16; i++) printf("%02X", w[(round)*16+i]);
  }

  /* 4. Final Round */
  SubBytes();
  ShiftRows();
  AddRoundKey(Nr);

  /* Lay du lieu ra theo cot*/
  for (int i = 0; i < 16; i++)
  {
    output[i] = state[(i % 4) * 4 + (i / 4)];
  }
}

/* Cac ham phuc vu qua trinh giai ma */
/* Dich vong sang phai 1 byte */
void InvShiftRows(void)
{
  unsigned char temp[4 * 4];

  for (int i = 1; i < 4; i++)
    for (int j = 0; j < 4; j++)
    {
      temp[i * 4 + j] = state[i * 4 + j];
    }

  /* lay nguoc cua phep bien doi o ShiftRows o tren */
  for (int i = 1; i < 4; i++)
    for (int j = 0; j < 4; j++)
    {
      state[i * 4 + ((i + j) % 4)] = temp[i * 4 + j];
    }
}

/* Thuc hien phep the nguoc - thong qua bang the nguoc invSBox */
void InvSubBytes(void)
{
  int x, y;
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
    {
      // x= (unsigned char)((int)(state[i*4+j])>>4);
      // y= (unsigned char)((int)(state[i*4+j])&0x0f);
      state[i * 4 + j] = invSBox[state[i * 4 + j]];
    }
}

void InvMixColumns(void)
{
  unsigned char temp[4 * 4];

  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
    {
      temp[i * 4 + j] = state[i * 4 + j];
    }
  //ma tran goc
  for (int i = 0; i < 4; i++)
  {

    state[0 * 4 + i] = (unsigned char)((int)gfMultBy0e(temp[0 * 4 + i]) ^
                                       (int)gfMultBy0b(temp[1 * 4 + i]) ^
                                       (int)gfMultBy0d(temp[2 * 4 + i]) ^
                                       (int)gfMultBy09(temp[3 * 4 + i]));

    state[1 * 4 + i] = (unsigned char)((int)gfMultBy09(temp[0 * 4 + i]) ^
                                       (int)gfMultBy0e(temp[1 * 4 + i]) ^
                                       (int)gfMultBy0b(temp[2 * 4 + i]) ^
                                       (int)gfMultBy0d(temp[3 * 4 + i]));

    state[2 * 4 + i] = (unsigned char)((int)gfMultBy0d(temp[0 * 4 + i]) ^
                                       (int)gfMultBy09(temp[1 * 4 + i]) ^
                                       (int)gfMultBy0e(temp[2 * 4 + i]) ^
                                       (int)gfMultBy0b(temp[3 * 4 + i]));

    state[3 * 4 + i] = (unsigned char)((int)gfMultBy0b(temp[0 * 4 + i]) ^
                                       (int)gfMultBy0d(temp[1 * 4 + i]) ^
                                       (int)gfMultBy09(temp[2 * 4 + i]) ^
                                       (int)gfMultBy0e(temp[3 * 4 + i]));
  }
}

// Ham thuc hien giai ma AES
void InvAES_Cipher(unsigned char *input, unsigned char *output)
{
  /* Neu input hoac output chua khoi tao -> THOAT */
  if (input == NULL || output == NULL)
    return;

  /* 1. Dua input vao State */
  for (int i = 0; i < 16; i++)
  {
    /* theo cot */
    state[(i % 4) * 4 + (i / 4)] = input[i];
  }

  /* 2. AddRoundKey - Khoa cua vong thu Nr*/
  AddRoundKey(Nr);

  /* 3. Thuc hien Nr vong lap nguoc */
  for (int round = Nr - 1; round >= 1; --round)
  {
    InvShiftRows();
    InvSubBytes();
    AddRoundKey(round);
    InvMixColumns();
  }

  /* 4. Final Round */
  InvShiftRows();
  InvSubBytes();
  AddRoundKey(0);

  /* Lay du lieu ra - theo cot*/
  for (int i = 0; i < 16; i++)
  {
    output[i] = state[(i % 4) * 4 + (i / 4)];
  }
}

string get_input_from_keyboard()
{
  string input;
  cin >> input;
  return input;
}

string get_input_from_file(string path)
{
  ifstream inFile;
  inFile.open(path);

  stringstream strStream;
  strStream << inFile.rdbuf();
  string str = strStream.str();
  return str;
}

int main()
{
  unsigned char pBlock[100][16], cBlock[100][16], bdich[16], bma[16];
  unsigned char khoa[32]; /* 256 bit */
  unsigned char testvectors2[16] = {0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87};
  int k;

  string ban_ro, ban_ma, ban_dich;
  int chon;

  do
  {
    cout << "|------HAY NHAP LUA CHON---------|\n";
    cout << "|1: Nhap tu ban phim             |\n";
    cout << "|2: Doc tu file input.txt        |\n";
    cout << "|________________________________|\n";
    cout << "chon: ";
    cin >> chon;
  } while (chon < 1 || chon > 2);

  switch (chon)
  {
  case 1:
    ban_ro = get_input_from_keyboard();
    break;
  case 2:
    ban_ro = get_input_from_file("input.txt");
    break;
  default:
    break;
  }

  int i = 0, dem = 1;
  while (i < ban_ro.size())
  {
    unsigned char bro[16];
    for (int j = 0; j < 16; j++)
    {
      if (i + j > ban_ro.size())
      {
        bro[j] = '0';
      }
      else
      {
        bro[j] = ban_ro[i + j];
      }
    }

    /* Khoa ma/dich - 128 bit */
    for (int i = 0; i < 16; i++)
      khoa[i] = (unsigned char)i;

    /* In ban ro */
    printf("\n\nKhoi ban ro thu %d : ", dem);
    for (int i = 0; i < 16; i++)
      printf("%02X", bro[i]);
    printf("\n Khoa : ");
    for (int i = 0; i < 16; i++)
      printf("%02X", khoa[i]);

    /* 1. Thiet lap so khoa su dung */
    SetNkNr(128);
    /* 2. Thiet lap khoa con */
    KeyExpantion(khoa, w);
    /* 3. Goi ham ma */
    printf("\nStarting Encrypt...");

    AES_Cipher(bro, bma);

    /* In ket qua ma */
    printf("\nKhoi ban ma thu %d : ", dem);
    for (int i = 0; i < 16; i++)
      printf("%02X", bma[i]);

    for (int j = 0; j < 16; j++)
    {
      ban_ma += bma[j];
    }
    i += 16;
    dem++;
  }

  cout << "\nBan ro ban dau        : " << ban_ro;
  cout << "\nBan ma sau khi ma hoa : " << ban_ma << "\n\n";

  /* ***************************************/
  /* Mo phong qua trinh dich cua AES */
  /* Lay ban ma lam dau vao cho ma hoa */
  /* ***************************************/

  i = 0, dem = 1;
  while (i < ban_ma.size())
  {
    for (int j = 0; j < 16; j++)
    {
      if (i + j > ban_ma.size())
      {
        bma[j] = '0';
      }
      else
      {
        bma[j] = ban_ma[i + j];
      }
    }
    /* 1. Tao bang hoan vi nguoc */
    InitInvSBox();

    /* 2. Thiet lap khoa con */
    KeyExpantion(khoa, w);
    /* 3. Goi ham giai ma*/
    InvAES_Cipher(bma, bdich);

    /* In ket qua dich */
    printf("\nKhoi ban dich thu %d: ", dem);
    for (int i = 0; i < 16; i++)
      printf("%02X", bdich[i]);

    for (int j = 0; j < 16; j++) // noi khoi vua giai ma vao ket qua ban dich
    {
      ban_dich += bdich[j];
    }
    i += 16;
    dem++;
  }
  cout << "\nBan ma  : " << ban_ma;
  cout << "\nBan dich: " << ban_dich;

  printf("\nAn phim bat ky de thoat chuong trinh : ");
  getch();
  return 0;
}
