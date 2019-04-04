using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {

        class Sbox
        {
            public static readonly byte[] sBox = new byte[256] {
            //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F


            public static readonly byte[] inverseSBox = new byte[256] {
            //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, //0
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, //1
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, //2
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, //3
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, //4
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, //5
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, //6
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, //7
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, //8
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, //9
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, //A
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, //B
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, //C
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, //D
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, //E
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D }; //F
        }

        byte[,] Key = new byte[4, 4];

        void parse(string input,ref byte[,] Entry)
        {
            input=input.Replace("0x", "");
            for (int i=0;i<input.Length;i+=2)
            {
                string temp = "";
                temp += input[i];
                temp += input[i + 1];
                Entry[(i / 2) % 4, Math.Min((i / 2) / 4, 3)] = byte.Parse(temp,System.Globalization.NumberStyles.HexNumber);
            }
        }

        public static readonly byte[] rcon = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

        byte substitute(int entry)
        {
            string hex = Convert.ToString(entry, 16);
            hex = hex.Replace("0x", "").Replace("x", "");
            int i;
            if (hex.Length == 2)
                i = Convert.ToInt32(hex.Substring(0, hex.Length / 2), 16);
            else
                i = 0;
            int j = Convert.ToInt32(hex.Substring(hex.Length / 2, Math.Max((hex.Length / 2),1)),16);
            return Sbox.sBox[i*16+j];
        }

        byte substituteInv(int entry)
        {
            string hex = Convert.ToString(entry, 16);
            hex = hex.Replace("0x", "").Replace("x", "");
            int i;
            if (hex.Length == 2)
                i = Convert.ToInt32(hex.Substring(0, hex.Length / 2), 16);
            else
                i = 0;
            int j = Convert.ToInt32(hex.Substring(hex.Length / 2, Math.Max((hex.Length / 2), 1)), 16);
            return Sbox.inverseSBox[i * 16 + j];
        }

        private byte GalioModuleMul(byte A, byte B)
        {
            byte outBound = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((B & 1) != 0)
                {
                    outBound ^= A;
                }
                bool carry = (A & 0x80) != 0; //Wheather the first byte is 1
                                              //Anding with 10000000 then comparing to 0
                A <<= 1;
                if (carry)
                {
                    A ^= 0x1B;
                }
                B >>= 1;
            }
           return outBound;
        }

        public byte[][] MixColumns(byte[][] Columns)
        {
            //Mixing Matrix
            //2     3       1       1
            //1     2       3       1
            //1     1       2       3
            //3     1       1       2
            byte[][] OutBound = new byte[4][];
            OutBound[0] = new byte[4] { 0, 0, 0, 0 };
            OutBound[1] = new byte[4] { 0, 0, 0, 0 };
            OutBound[2] = new byte[4] { 0, 0, 0, 0 };
            OutBound[3] = new byte[4] { 0, 0, 0, 0 };
            for (int c = 0; c < 4; c++)
            {
                OutBound[0][c] = (byte)(GalioModuleMul(0x02, Columns[0][c]) ^
                    GalioModuleMul(0x03, Columns[1][c]) ^
                    GalioModuleMul(0x01,Columns[2][c]) ^
                    GalioModuleMul(0x01,Columns[3][c]));
                OutBound[1][c] = (byte)(GalioModuleMul(0x01, Columns[0][c]) ^
                    GalioModuleMul(0x02, Columns[1][c]) ^
                    GalioModuleMul(0x03, Columns[2][c]) ^
                    GalioModuleMul(0x01, Columns[3][c]));
                OutBound[2][c] = (byte)(GalioModuleMul(0x01, Columns[0][c]) ^
                    GalioModuleMul(0x01, Columns[1][c]) ^
                    GalioModuleMul(0x02, Columns[2][c]) ^
                    GalioModuleMul(0x03, Columns[3][c]));
                OutBound[3][c] = (byte)(GalioModuleMul(0x03, Columns[0][c]) ^
                    GalioModuleMul(0x01, Columns[1][c]) ^
                    GalioModuleMul(0x01, Columns[2][c]) ^
                    GalioModuleMul(0x02, Columns[3][c]));

            }
            return OutBound;
        }

        public byte[][] unMixColumns(byte[][] Columns)
        {
            //unMixing Matrix
            //e     b       d       9
            //9     e       b       d
            //d     9       e       b
            //b     d       9       e
            byte[][] OutBound = new byte[4][];
            OutBound[0] = new byte[4] { 0, 0, 0, 0 };
            OutBound[1] = new byte[4] { 0, 0, 0, 0 };
            OutBound[2] = new byte[4] { 0, 0, 0, 0 };
            OutBound[3] = new byte[4] { 0, 0, 0, 0 };
            for (int c = 0; c < 4; c++)
            {
                OutBound[0][c] = (byte)(GalioModuleMul(0x0e, Columns[0][c]) ^ 
                    GalioModuleMul(0x0b, Columns[1][c]) ^ 
                    GalioModuleMul(0x0d,Columns[2][c]) ^ 
                    GalioModuleMul(0x09,Columns[3][c]));
                OutBound[1][c] = (byte)(GalioModuleMul(0x09,Columns[0][c]) ^ 
                    GalioModuleMul(0x0e, Columns[1][c]) ^ 
                    GalioModuleMul(0x0b, Columns[2][c]) ^
                    GalioModuleMul(0x0d,Columns[3][c]));
                OutBound[2][c] = (byte)(GalioModuleMul(0x0d, Columns[0][c]) ^
                    GalioModuleMul(0x09, Columns[1][c]) ^
                    GalioModuleMul(0x0e, Columns[2][c]) ^
                    GalioModuleMul(0x0b, Columns[3][c]));
                OutBound[3][c] = (byte)(GalioModuleMul(0x0b, Columns[0][c]) ^
                    GalioModuleMul(0x0d, Columns[1][c]) ^
                    GalioModuleMul(0x09, Columns[2][c]) ^
                    GalioModuleMul(0x0e, Columns[3][c]));
            }
            return OutBound;
        }

        public byte[,] FGenerateRoundKey(byte[,] Key0,int round)
        {
            byte[,] Key1 = new byte[4, 4];

            //Rotating and substitution single step
            Key1[0, 0] = substitute(Key0[1, 3]);
            Key1[1, 0] = substitute(Key0[2, 3]);
            Key1[2, 0] = substitute(Key0[3, 3]);
            Key1[3, 0] = substitute(Key0[0, 3]);

            //XOR with Round Constant
            Key1[0, 0] = (byte)(Key1[0, 0]^Key0[0, 0]^rcon[round-1]);
            Key1[1, 0] = (byte)(Key1[1, 0]^Key0[1, 0]^0x0);
            Key1[2, 0] = (byte)(Key1[2, 0]^Key0[2, 0]^0x0);
            Key1[3, 0] = (byte)(Key1[3, 0]^Key0[3, 0]^0x0);

            //XORing with correspodning columns
            for (int i = 1;i<4;i++)
            {
                Key1[0, i] = (byte)(Key1[0, i-1] ^ Key0[0, i]);
                Key1[1, i] = (byte)(Key1[1, i-1] ^ Key0[1, i]);
                Key1[2, i] = (byte)(Key1[2, i-1] ^ Key0[2, i]);
                Key1[3, i] = (byte)(Key1[3, i-1] ^ Key0[3, i]);
            }

            return Key1;
        }

        //Used mainly for debugging
        //changes the byte arrays to understandable hexadecimal
        string fromArrtoStr(byte[,] input)
        {
            string outBound = "";
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    outBound += input[i, j].ToString("X").PadLeft(2, '0');
            return outBound;
        }

        public override string Decrypt(string cipherText, string key)
        {
            key = key.ToLower();
            cipherText = cipherText.Replace("0x", "").ToLower();
            int deciphered = 0;
            parse(key, ref Key);
            byte[][,] Keys = new byte[11][,];
            Keys[0] = Key;
            for (int i=1;i<11;i++)
            {
                Keys[i] = FGenerateRoundKey(Keys[i - 1], i);
            }
            string outBound = "0x";
            while (deciphered < cipherText.Length)
            {
                byte[,] block = new byte[4, 4];
                parse(cipherText.Substring(0, 32), ref block);
                deciphered += 32;
                byte[,] CipheredClass=new byte[4,4];
                byte[][] ColumnsMixed;
                byte[][] RowsShifted;
                byte[,] subCiphered;

                //debug
                string RoundOut;

                //Intial Addition
                for (int i = 0; i < 4; i++)
                {
                    block[0, i] = (byte)(block[0, i] ^ Keys[10][0, i]);
                    block[1, i] = (byte)(block[1, i] ^ Keys[10][1, i]);
                    block[2, i] = (byte)(block[2, i] ^ Keys[10][2, i]);
                    block[3, i] = (byte)(block[3, i] ^ Keys[10][3, i]);
                }
                RoundOut = fromArrtoStr(block);
                //itirative
                for (int round = 9; round >=0; round--)
                {
                    //byte substitution
                    subCiphered = new byte[4, 4];
                    for (int i = 0; i < 4; i++)
                        for (int j = 0; j < 4; j++)
                            subCiphered[i, j] = substituteInv(block[i, j]);

                    RowsShifted = new byte[4][];
                    //Shift Rows
                    for (int i = 0; i < 4; i++)
                    {
                        RowsShifted[i] = new byte[4];
                        RowsShifted[i][0] = subCiphered[i, (4-i) % 4];
                        RowsShifted[i][1] = subCiphered[i, (5-i) % 4];
                        RowsShifted[i][2] = subCiphered[i, (6-i) % 4];
                        RowsShifted[i][3] = subCiphered[i, (7-i) % 4];

                    }

                    CipheredClass = new byte[4, 4];

                    //Adding Round Key
                    for (int i = 0; i < 4; i++)
                    {
                        CipheredClass[0, i] = (byte)(RowsShifted[0][i] ^ Keys[round][0,i]);
                        CipheredClass[1, i] = (byte)(RowsShifted[1][i] ^ Keys[round][1,i]);
                        CipheredClass[2, i] = (byte)(RowsShifted[2][i] ^ Keys[round][2,i]);
                        CipheredClass[3, i] = (byte)(RowsShifted[3][i] ^ Keys[round][3,i]);
                    }
                    string beforeMix = fromArrtoStr(CipheredClass);

                    byte[][] preMix = new byte[4][];
                    preMix[0] = new byte[4];
                    preMix[1] = new byte[4];
                    preMix[2] = new byte[4];
                    preMix[3] = new byte[4];
                    for (int i = 0; i < 4; i++)
                    {
                        preMix[0][i]=CipheredClass[0, i];
                        preMix[1][i]=CipheredClass[1, i];
                        preMix[2][i]=CipheredClass[2, i];
                        preMix[3][i]=CipheredClass[3, i];
                    }

                    //Unmixing Columns
                    if (round != 0)
                        ColumnsMixed = unMixColumns(preMix);
                    else
                        ColumnsMixed = preMix;

                    for (int i = 0; i < 4; i++)
                    {
                        CipheredClass[0, i]= ColumnsMixed[0][i];
                        CipheredClass[1, i]= ColumnsMixed[1][i];
                        CipheredClass[2, i]= ColumnsMixed[2][i];
                        CipheredClass[3, i] = ColumnsMixed[3][i];
                    }
                    RoundOut = fromArrtoStr(CipheredClass);
                    block = CipheredClass;
                }
                //serializing and realigning output
                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < 4; j++)
                        outBound += CipheredClass[j, i].ToString("X").PadLeft(2, '0');
            }
            return outBound;
        }

        public override string Encrypt(string plainText, string key)
        {
            key = key.ToLower();
            plainText = plainText.Replace("0x", "").ToLower();
            int ciphered = 0;
            parse(key, ref Key);
            string outBound = "0x";
            while (ciphered < plainText.Length)
            {
                byte[,] block = new byte[4, 4];
                parse(plainText.Substring(0, 32), ref block);
                ciphered += 32;

                //FirstRound
                byte[,] Key1 = FGenerateRoundKey(Key, 1);
                //intialRound
                for (int i = 0; i < 4; i++)
                {
                    block[0, i] = (byte)(block[0,i] ^ Key[0, i]);
                    block[1, i] = (byte)(block[1,i] ^ Key[1, i]);
                    block[2, i] = (byte)(block[2,i] ^ Key[2, i]);
                    block[3, i] = (byte)(block[3,i] ^ Key[3, i]);
                }

                string inputToRound = fromArrtoStr(block); //debug variables

                //byte substitution
                byte[,] subCiphered = new byte[4, 4];
                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < 4; j++)
                        subCiphered[i, j] = substitute(block[i, j]);

                string afterSbox = fromArrtoStr(subCiphered);

                byte[][] RowsShifted = new byte[4][];
                //Shift Rows
                for (int i=0;i<4;i++)
                {
                    RowsShifted[i] = new byte[4];
                    RowsShifted[i][0] = subCiphered[i, (i+4) % 4];
                    RowsShifted[i][1] = subCiphered[i, (i+5) % 4];
                    RowsShifted[i][2] = subCiphered[i, (i+6) % 4];
                    RowsShifted[i][3] = subCiphered[i, (i+7) % 4];
                }

                //Mix Columns
                byte[][] ColumnsMixed = MixColumns(RowsShifted);

                byte[,] CipheredClass = new byte[4, 4];
                //Adding Round Key
                for (int i=0;i<4;i++)
                {
                    CipheredClass[0, i] = (byte)(ColumnsMixed[0][i] ^ Key1[0, i]);
                    CipheredClass[1, i] = (byte)(ColumnsMixed[1][i] ^ Key1[1, i]);
                    CipheredClass[2, i] = (byte)(ColumnsMixed[2][i] ^ Key1[2, i]);
                    CipheredClass[3, i] = (byte)(ColumnsMixed[3][i] ^ Key1[3, i]);
                }
                string RoundOut = fromArrtoStr(CipheredClass);
                //itirative
                for (int round=1; round < 10; round++)
                {
                    block = CipheredClass;

                    Key1 = FGenerateRoundKey(Key1, round + 1);

                    //byte substitution
                    subCiphered = new byte[4, 4];
                    for (int i = 0; i < 4; i++)
                        for (int j = 0; j < 4; j++)
                            subCiphered[i, j] = substitute(block[i, j]);

                    RowsShifted = new byte[4][];
                    //Shift Rows
                    for (int i = 0; i < 4; i++)
                    {
                        RowsShifted[i] = new byte[4];
                        RowsShifted[i][0] = subCiphered[i, (i + 4) % 4];
                        RowsShifted[i][1] = subCiphered[i, (i + 5) % 4];
                        RowsShifted[i][2] = subCiphered[i, (i + 6) % 4];
                        RowsShifted[i][3] = subCiphered[i, (i + 7) % 4];
                    }

                    //Mix Columns
                    if (round != 9)
                        ColumnsMixed = MixColumns(RowsShifted);
                    else
                        ColumnsMixed = RowsShifted;

                    CipheredClass = new byte[4, 4];
                    //Adding Round Key
                    for (int i = 0; i < 4; i++)
                    {
                        CipheredClass[0, i] = (byte)(ColumnsMixed[0][i] ^ Key1[0, i]);
                        CipheredClass[1, i] = (byte)(ColumnsMixed[1][i] ^ Key1[1, i]);
                        CipheredClass[2, i] = (byte)(ColumnsMixed[2][i] ^ Key1[2, i]);
                        CipheredClass[3, i] = (byte)(ColumnsMixed[3][i] ^ Key1[3, i]);
                    }
                    RoundOut = fromArrtoStr(CipheredClass);
                }

                //serializing and realigning output
                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < 4; j++)
                        outBound += CipheredClass[j, i].ToString("X").PadLeft(2,'0');
            }
            return outBound;
        }
    }
}
