using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {

        List<string> Columnize(string text,int columnsCount)
        {
            List<string> Columns = new List<string>();
            int ExpectedPadding1 = columnsCount - (text.Length % columnsCount);
            int curDepth = (text.Length / columnsCount) + 1;
            int offset = 0;
            for (int i = 0; i < columnsCount; i++)
            {
                if (i == columnsCount - ExpectedPadding1) { curDepth -= 1; }
                string Column = "";
                for (int j = 0; j < curDepth; j++)
                {
                    Column += text[j + offset];
                }
                Columns.Add(Column);
                offset += curDepth;
            }
            return Columns;
        }
        public List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            Dictionary<char, List<int>> CTAnalysis = new Dictionary<char, List<int>>();
            Dictionary<char, List<int>> PTAnalysis = new Dictionary<char, List<int>>();

            for (int i = 0; i < plainText.Length; i++)
            {
                if (!PTAnalysis.ContainsKey(plainText[i])) { PTAnalysis.Add(plainText[i], new List<int>()); }
                PTAnalysis[plainText[i]].Add(i);
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (!CTAnalysis.ContainsKey(cipherText[i])) { CTAnalysis.Add(cipherText[i], new List<int>()); }
                CTAnalysis[cipherText[i]].Add(i);
            }

            int minFollow = int.MaxValue;
            int minFollowIndex = -1;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (PTAnalysis[plainText[i]].Count==1 && i<plainText.Length-1)
                {
                    if (PTAnalysis[plainText[i+1]].Count < minFollow)
                    {
                        minFollow = PTAnalysis[plainText[i+1]].Count;
                        minFollowIndex = i + 1;
                    }
                }
            }

            if (minFollowIndex==-1)
            {
                throw new InvalidAnlysisException();
            }

            int Depth = 0;
            int streak = int.MinValue;
            foreach (int index in CTAnalysis[plainText[minFollowIndex]])
            {
                int aIndex = CTAnalysis[plainText[minFollowIndex-1]].First();
                int delta = index - aIndex;
                if (delta > plainText.Length / 2) { }
                int i = 1;
                int localStreak = 0;
                while (aIndex + i +delta<cipherText.Length && aIndex + i < cipherText.Length)
                {
                    string s = "";
                    s += cipherText[aIndex + i];
                    s += cipherText[aIndex + i + delta];
                    if (plainText.Contains( s ))
                    {
                        localStreak++;
                    }
                    else
                    {
                        break;
                    }
                    i++;
                }
                if (localStreak>streak)
                {
                    streak = localStreak;
                    Depth=delta;
                }
            }

            for (int a = streak*3; a !=0; a--)
            {
                int[] Key = new int[a];
                var tempKey = new List<int>();
                tempKey.AddRange(Enumerable.Range(1, a));
                string Stemp = Encrypt(plainText, tempKey);

                List<string> CT = Columnize(cipherText, a);
                List<string> CTx = Columnize(Stemp, a);

                for (int i = 0; i < CT.Count; i++)
                {
                    for (int j = 0; j < CTx.Count; j++)
                    {
                        if (CT[i] == CTx[j])
                        {
                            Key[j] = i + 1;
                        }
                    }
                }

                if (!Key.Contains(0))
                    return Key.ToList();
            }
            return new int[streak*3].ToList();
            throw new InvalidAnlysisException();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            string Outbount = "";
            string[] columns = new string[key.Count];
            string[] SortedColumns = new string[key.Count];
            int ExpectedPadding = key.Count - (cipherText.Length % key.Count);
            int Depth = (cipherText.Length / key.Count)+1;
            int offset = 0;
            for (int i=0;i<key.Count;i++)
            {
                if (i == key.Count - ExpectedPadding) { Depth -= 1; }
                for (int j = 0;j<Depth;j++)
                {
                    columns[i] += cipherText[offset + j];
                }
                offset += Depth;
            }
            for (int i = 0; i < key.Count; i++) { SortedColumns[i] = columns[key[i] - 1]; }

            for (int j = 0;j< (cipherText.Length / key.Count) + 1; j ++)
            {
                for (int i = 0; i < SortedColumns.Length; i++)
                {
                    if (SortedColumns[i].Length-1<j)
                    {
                        break;
                    }
                    Outbount += SortedColumns[i][j];
                }
            }
            return Outbount;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            string Outbount = "";
            string[] columns = new string[key.Count];
            string[] SortedColumns = new string[key.Count];
            foreach (int i in key)
            {
                int index = i - 1;
                for (int j = 0; ; j += key.Count)
                {
                    if (index + j > plainText.Length - 1) { break; }
                    columns[index] += plainText[index + j];
                }
            }
            for (int i = 0;i<key.Count;i++ ) { SortedColumns[key[i] - 1] = columns[i]; }
            foreach (string s in SortedColumns) { Outbount += s; }
            return Outbount;
        }
    }
}
