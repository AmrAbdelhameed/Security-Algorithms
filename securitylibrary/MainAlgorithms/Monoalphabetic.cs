using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            string Alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToLower();
            SortedDictionary<char, char> KeyTable = new SortedDictionary<char, char>();
            Dictionary<char, bool> AlphaList = new Dictionary<char, bool>();

            for (int i = 0; i < plainText.Length; i++)
            {
                if (!KeyTable.ContainsKey(plainText[i])) 
                { 
                    KeyTable.Add(plainText[i], cipherText[i]);
                    AlphaList.Add(cipherText[i], true); 
                }
            }

            for (int i = 0; i < 26; i++)
            {
                if (!KeyTable.ContainsKey(Alpha[i]))
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (!AlphaList.ContainsKey(Alpha[j]))
                        {
                            KeyTable.Add(Alpha[i], Alpha[j]);
                            AlphaList.Add(Alpha[j], true);
                            break;
                        }
                    }
                }
            }

            string key = string.Empty;
            foreach (var item in KeyTable)
                key += item.Value;
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string output = string.Empty;
            foreach (char ch in cipherText)
            {
                if (!char.IsLetter(ch))
                    output += ch;
                else
                    output += (char)(key.IndexOf(ch) + 97);
            }
            return output;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            string output = string.Empty;
            foreach (char ch in plainText)
            {
                if (!char.IsLetter(ch))
                    output += ch;
                else
                    output += key[ch - 97];
            }
            return output;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            string alphabetFreq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            SortedDictionary<char, char> KeyTable = new SortedDictionary<char, char>();
            Dictionary<char, int> CipherAlphaFreq = new Dictionary<char, int>();

            foreach (char ch in cipher)
            {
                if (!CipherAlphaFreq.ContainsKey(ch))
                    CipherAlphaFreq.Add(ch, 0);
                else
                    CipherAlphaFreq[ch]++;
            }

            CipherAlphaFreq = CipherAlphaFreq.OrderBy(x => x.Value)
                                    .Reverse().ToDictionary(x => x.Key, x => x.Value);
            int counter = 0;
            foreach (var item in CipherAlphaFreq)
            {
                KeyTable.Add(item.Key, alphabetFreq[counter]);
                counter++;
            }

            string key = string.Empty;
            foreach (char ch in cipher)
                key += KeyTable[ch];
            return key;
        }
    }
}
