using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES des = new DES();
            string pt = des.Decrypt(cipherText, key[1]);
            pt = des.Encrypt(pt, key[0]);
            pt = des.Decrypt(pt, key[1]);
            return pt;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES des = new DES();
            string ct = des.Encrypt(plainText, key[0]);
            ct = des.Decrypt(ct, key[1]);
            ct = des.Encrypt(plainText, key[0]);
            return ct;
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }
    }
}
