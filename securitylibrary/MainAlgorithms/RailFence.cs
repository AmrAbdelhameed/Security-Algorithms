using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        private string transform(string str, int key, bool f)
        {
            //if f = 0 plain to cipher meaning upper
            //else lower
            List<List<char>> mat = new List<List<char>>();

            for (int i = 0; i < key; i++)
                mat.Add(new List<char>());

            for (int j = 0, i = 0; i < str.Length; i++, j = (j + 1) % key)
            {
                mat[j].Add(str[i]);
            }

            char[] returnText = new char[str.Length];

            for (int i = 0, ptr = 0; i < key; i++)
            {
                for (int j = 0; j < mat[i].Count; j++)
                {
                    returnText[ptr++] = mat[i][j];
                }
            }
            if(!f)
                return new string(returnText).ToUpper();
            return new string(returnText).ToLower();
        }
        public int Analyse(string plainText, string cipherText)
        {   
            var builder = new StringBuilder();
            foreach(char c in plainText)
                builder.Append(c);
            while (builder.Length < cipherText.Length)
                builder.Append('x');
            plainText = builder.ToString(); 
            int ans = -1;
            for (int key = 1; key <= plainText.Length; key++)
            {
                if(transform(plainText,key,false) == cipherText)
                {
                    ans = key;
                    break;
                }
            }
            if (ans == -1)
                throw new InvalidAnlysisException();
            return ans;
        }

        public string Decrypt(string cipherText, int key)
        {
            return transform(cipherText, (cipherText.Length + key - 1) / key, true);
        }

        public string Encrypt(string plainText, int key)
        {
            string ret = transform(plainText, key,false);
            Console.WriteLine(ret);
            Console.WriteLine(plainText);
            return ret;
        }
    }
}
