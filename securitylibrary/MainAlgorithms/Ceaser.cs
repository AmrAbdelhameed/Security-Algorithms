using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string output = string.Empty;
            foreach (char ch in plainText)
                output += Helper(ch, key);
            return output;  
        }

        public string Decrypt(string cipherText, int key)
        {
            return Encrypt(cipherText, 26 - key);
        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int i = 0;
            while (true)
            {
                if (Encrypt(plainText, i).Equals(cipherText))
                    return i;
                i++;
            }
        }

        public char Helper(char ch, int key)
        {
            if (char.IsLetter(ch))
            {
                char chLower = char.IsUpper(ch) ? 'A' : 'a';
                return (char)((((ch + key) - chLower) % 26) + chLower);
            }
            return ch;
        }  
    }
}
