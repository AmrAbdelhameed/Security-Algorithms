using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            Queue<char> Pathfinder = new Queue<char>(); //RepeatedKey Removal
            Queue<char> PathReserve = new Queue<char>();

            bool streak = false;  //Wheather or not the currently parsed character is a part of a repeat
            string nonRep = ""; //The Key without repeatations
            string Key = ""; //The key repeated
            string PT = plainText.ToLower();
            string CT = cipherText.ToLower();
            for (int i = 0; i < plainText.Length; i++)
            {
                char Temp = (char)(CT[i] - (PT[i] - 'a'));
                if (Temp < 'a')
                {
                    int index = 26 - (PT[i] - 'a');
                    Temp = (char)(CT[i] + index);
                }
                if (Pathfinder.Count==0 || Temp != Pathfinder.Peek())
                {
                    Key += Temp;
                    Pathfinder.Enqueue(Temp);
                    nonRep = Key;
                    if (streak)
                    {
                        Pathfinder.Clear();
                        PathReserve.Clear();
                        foreach (char c in nonRep)
                        {
                            Pathfinder.Enqueue(c);
                        }
                        streak = false;
                    }
                }
                else
                {
                    Key += Temp;
                    PathReserve.Enqueue(Pathfinder.Dequeue());
                    streak = true;
                }
                if (Pathfinder.Count==0 && streak)
                {
                    while (PathReserve.Count!=0)
                    {
                        Pathfinder.Enqueue(PathReserve.Dequeue());
                    }
                    streak = false;
                }
            }
            return nonRep;
        }

        public string Decrypt(string cipherText, string key)
        {
            string PT = "";
            string CT = cipherText.ToLower();
            for (int i = 0; i < CT.Length; i++)
            {
                char Temp = (char)(CT[i] - (key[i % key.Length] - 'a'));
                if (Temp < 'a')
                {
                    int index = 26 - (key[i % key.Length] - 'a');
                    Temp = (char)(CT[i] + index);
                }
                PT += Temp;
            }
            return PT;
        }

        public string Encrypt(string plainText, string key)
        {
            string PT = plainText.ToLower();
            string CT = "";
            for(int i=0;i<plainText.Length;i++)
            {
                char Temp = (char)(plainText[i] + (key[i % key.Length]-'a'));
                if (Temp > 'z')
                {
                    Temp = (char)(Temp % 'z');
                    Temp += (char)('a'- 1);
                }
                CT += Temp;
            }
            return CT.ToUpper();
        }
    }
}