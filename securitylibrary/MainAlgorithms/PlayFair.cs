using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToUpper();
            string str = ConstructMatrix(key);
            string DecryptString = "";

            for (int i = 0; i < cipherText.Length; i += 2)
            {
                char x = cipherText[i];
                char y = cipherText[i + 1];
                int posX = str.IndexOf(x);
                int posY = str.IndexOf(y);

                DecryptString += decrptText(posX, posY, str);
            }
            string newstr = "";
            for (int i = 0; i < DecryptString.Length; i++)
            {
                if ((i + 1) == DecryptString.Length)
                {
                    if (DecryptString[i] != 'X')
                        newstr += DecryptString[i];
                    break;
                }
                if ((i + 2) >= DecryptString.Length)
                {
                    newstr += DecryptString[i];
                    if (DecryptString[i+1] != 'X')
                        newstr += DecryptString[i+1];
                    break;
                }
                char x = DecryptString[i];
                char y = DecryptString[i + 1];
                char z = DecryptString[i + 2];
                if (x == z && y == 'X'&&i%2==0)
                {
                    newstr += x;
                    newstr += z;
                    i += 2;
                }
                else
                {
                    newstr += DecryptString[i];
                }
            }
            DecryptString = newstr;
            return DecryptString;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToUpper();
            string newplain = "";
            for (int i = 0; i < plainText.Length; i += 2)
            {
                if (i + 1 == plainText.Length)
                {
                    newplain += plainText[i];
                    break;
                }
                char x = plainText[i];
                char y = plainText[i + 1];
                if (x == y)
                {
                    newplain += x;
                    newplain += "X";
                    i--;
                }
                else
                {
                    newplain += x;
                    newplain += y;
                }
            }
            plainText = newplain;
            string str = ConstructMatrix(key);
            string EncryptString = "";
            if (plainText.Length % 2 != 0)
            {
                plainText += "X";
            }
            for (int i = 0; i < plainText.Length; i += 2)
            {
                char x = plainText[i];
                char y = plainText[i + 1];
                int posX = str.IndexOf(x);
                int posY = str.IndexOf(y);

                EncryptString += encrptText(posX, posY, str);
            }
            return EncryptString;
        }

        private string decrptText(int posX, int posY, string str)
        {
            string ans = "";
            int rowXx = posX / 5, colXx = posX % 5;
            int rowYy = posY / 5, colYy = posY % 5;
            if (rowXx == rowYy)
            {
                if (colYy > colXx)
                {
                    if (colXx != 0)
                        ans += str[posX - 1];
                    else
                        ans += str[posX + 4];
                    ans += str[posY - 1];
                }
                else if (colYy < colXx)
                {
                    ans += str[posX - 1];
                    if (colYy != 0)
                        ans += str[posY - 1];
                    else
                        ans += str[posY + 4];
                }
            }
            else if (colXx == colYy)
            {
                if (rowYy > rowXx)
                {
                    if (rowXx != 0)
                        ans += str[posX - 5];
                    else
                        ans += str[20 + colXx];
                    ans += str[posY - 5];
                }
                else if (rowYy < rowXx)
                {
                    ans += str[posX - 5];
                    if (rowYy != 0)
                        ans += str[posY - 5];
                    else
                        ans += str[20 + colYy];
                }
            }
            else
            {
                int newposY = rowXx * 5 + colYy;
                ans += str[newposY];

                int newposX = rowYy * 5 + colXx;
                ans += str[newposX];
            }

            return ans;
        }

        private string encrptText(int posX, int posY, string str)
        {
            string ans = "";
            int rowXx = posX / 5, colXx = posX % 5;
            int rowYy = posY / 5, colYy = posY % 5;
            if (rowXx == rowYy)
            {
                if (colYy > colXx)
                {
                    ans += str[posX + 1];
                    if (colYy != 4)
                        ans += str[posY + 1];
                    else
                        ans += str[posY - 4];
                }
                else if (colYy < colXx)
                {
                    if (colXx != 4)
                        ans += str[posX + 1];
                    else
                        ans += str[posX - 4];
                    ans += str[posY + 1];
                }
            }
            else if (colXx == colYy)
            {
                if (rowYy > rowXx)
                {
                    ans += str[posX + 5];
                    if (rowYy != 4)
                        ans += str[posY + 5];
                    else
                        ans += str[colYy];
                }
                else if (rowYy < rowXx)
                {
                    if (rowXx != 4)
                        ans += str[posX + 5];
                    else
                        ans += str[colXx];
                    ans += str[posY + 5];
                }
            }
            else
            {
                int newposY = rowXx * 5 + colYy;
                ans += str[newposY];
                int newposX = rowYy * 5 + colXx;
                ans += str[newposX];

            }

            return ans;
        }

        public string ConstructMatrix(string key)
        {
            key = key.ToUpper();
            char[,] array = new char[5, 5];
            string allchar = "";
            for (Char i = 'A'; i <= 'Z'; i++)
                allchar += i;
            string res = "";
            for (int i = 0; i < key.Length; i++)
            {
                if (res.Contains("I") && key[i] == 'J')
                    continue;
                if (res.Contains("J") && key[i] == 'I')
                    continue;
                if (!res.Contains(key[i]))
                {
                    res += key[i];
                }
            }
            for (int i = 0; i < allchar.Length; i++)
            {
                if (res.Contains("I") && allchar[i] == 'J')
                    continue;
                if (res.Contains("J") && allchar[i] == 'I')
                    continue;
                if (!res.Contains(allchar[i]))
                {
                    res += allchar[i];
                }
            }
            return res;
        }

    }
}
