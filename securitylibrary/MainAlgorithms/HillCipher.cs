using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        private List<int> matrixMul(List<List<int>> a, List<List<int>> b)
        {
            int r1 = a.Count;
            int c1 = a[0].Count;
            int r2 = b.Count;
            int c2 = b[0].Count;
            //assert c1 = r2
            ///result is of dimensions r1 * c2
            List<List<int>> resultMatrix = new List<List<int>>();
            for (int i = 0; i < r1; i++)
            {
                resultMatrix.Add(new List<int>());
                for (int j = 0; j < c2; j++)
                    resultMatrix[i].Add(0);
            }
            for (int i = 0; i < r1; i++)
            {
                for (int j = 0; j < c2; j++)
                {
                    for (int k = 0; k < c1; k++) //or r2
                    {
                        resultMatrix[i][j] = (resultMatrix[i][j] + a[i][k] * b[k][j]) % 26;
                    }
                }
            }
            List<int> resList = new List<int>();
            for (int i = 0; i < r1; i++)
            {
                for(int j = 0; j < c2; j++)
                   resList.Add(resultMatrix[i][j]);
            }
            return resList;
        }
        private int solveDeterminant(List<List<int>> mat)
        {
            if (mat.Count == 1)
                return mat[0][0];
            if (mat.Count == 2)
            {
                return mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0];
            }
            int r = mat.Count;
            int c = mat[0].Count;
            int ret = 0;
            for (int i = 0; i < 1; i++)
            {
                for (int j = 0; j < c; j++)
                {
                    List<List<int>> sendMatrix = new List<List<int>>();
                    for (int k = 0; k < r - 1; k++)
                        sendMatrix.Add(new List<int>());
                    for (int row = 0; row < r; row++)
                    {
                        if (row == i) continue;
                        for (int col = 0; col < c; col++)
                        {
                            if (col == j) continue;
                            sendMatrix[row - (row > i ? 1 : 0)].Add(mat[i][j]);
                        }
                    }
                    if(i == 0)
                     ret += (((i + j) % 2 == 1) ? -1 : 1) * solveDeterminant(sendMatrix) % 26;
                    ret %= 26;
                    if (ret < 0)
                        ret += 26;
                }
            }
            return ret;
        }
        private int gcd(int a, int b)
        {
            if (b == 0)
                return a;
            return gcd(b, a % b);
        }
        private List<List<int>> getInverseion(List<int> part)
        {
            List<List<int>> retMatrix = new List<List<int>>();
            retMatrix.Add(new List<int>());
            for (int i = 0; i < part.Count; i++)
                retMatrix[0].Add(part[i]);
            return retMatrix;   
        }
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            ///find a 2 * 2 Matrix such that C.T = P.T * x
            ///Consider the matrix multiplication
            ///CT[0] = Mat[0][0] * P.T[0] + Mat[0][1] * PT[1]
            ///so i have to satisfy that sum(Mat[i][j] * P[j]) = CT[i]
            if (plainText.Count != cipherText.Count)
                throw new InvalidAnlysisException();
            List<int> Key = new List<int>();
            bool f = false;
            for (int i = 0; i < cipherText.Count; i += 2)
            {
                if (i + 2 > cipherText.Count) break;
                List<int> plainPart = new List<int>();
                List<List<int>> cipherPart = new List<List<int>>();
                for (int j = 0; j < 2; j++)
                {
                    cipherPart.Add(new List<int>());
                    cipherPart[j].Add(cipherText[i + j]);
                    plainPart.Add(plainText[i+j]);
                }
                ///ct = key * pt
                ///key = ct * pt^-1
                List<List<int>> plainInversion = getInverseion(plainPart);
                List<int> append = matrixMul(cipherPart, plainInversion);
                if (!f)
                {
                    Key = append;
                }   else
                {
                    for (int x = 0; x < 4; x++)
                        if (Key[x] != append[x])
                            throw new InvalidAnlysisException();
                }
            }
            return Key;
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int m = 1;
            while (m * m < key.Count)
                m++;
            if (m * m != key.Count)
                throw new InvalidAnlysisException();
            //transform the key into 2D Matrix
            List<List<int>> keyMatrix = new List<List<int>>();
            List<List<int>> inv = new List<List<int>>();
            for (int i = 0; i < m; i++)
            {
                keyMatrix.Add(new List<int>());
                inv.Add(new List<int>());
            }
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    keyMatrix[i].Add(key[i * m + j]);
                }
            }

            int r = m;
            int c = m;
            int det = 0;
            for (int i = 0; i < r; i++)
            {
                for (int j = 0; j < c; j++)
                {
                    List<List<int>> sendMatrix = new List<List<int>>();
                    for (int k = 0; k < r - 1; k++)
                        sendMatrix.Add(new List<int>());
                    for (int row = 0; row < r; row++)
                    {
                        if (row == i) continue;
                        for (int col = 0; col < c; col++)
                        {
                            if (col == j) continue;
                            sendMatrix[row - (row > i ? 1 : 0)].Add(keyMatrix[row][col]);
                        }
                    }
                    inv[j].Add((((i + j) % 2 == 1)? -1 : 1) * solveDeterminant(sendMatrix) % 26);
                    if (inv[j][i] < 0)
                        inv[j][i] += 26;
                    if(i==0)
                       det += inv[j][i] * keyMatrix[i][j];
                    det %= 26;
                    if (det < 0)
                        det += 26;
                }
            }
            ///find the first element such that (26 * j + 1) % (26 - det) == 0
            ///gcd(det,26) = 1
            if(det == 0 || gcd(26, det) != 1)
            {
                throw new InvalidAnlysisException();
            }
            int mulInv = -1;
            for(int i = 0; ; i++)
            {
                if((i * 26 + 1) % (26 - det) == 0)
                {
                    mulInv = 26 - (i * 26 + 1) / (26 - det);
                    break;
                }
            }
            for(int i = 0; i < r; i++) {
                for(int j = 0; j < c; j++) {
                    inv[i][j] *= mulInv;
                    inv[i][j] %= 26;
                }
            }
            List<int> plainText = new List<int>();
            for (int i = 0; i < cipherText.Count; i += m)
            {
                List<List<int>> curPart = new List<List<int>>();
                for (int j = 0; j < m; j++)
                {
                    curPart.Add(new List<int>());
                    if (i + j < cipherText.Count)
                        curPart[j].Add(cipherText[i + j]);
                    else
                        curPart[j].Add(0);
                }
                List<int> append = matrixMul(inv, curPart);
                for (int j = 0; j < m && i + j < cipherText.Count; j++)
                {
                    plainText.Add(append[j]);
                }
            }

            return plainText;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int m = 1;
            while (m * m < key.Count)
                m++;
            if (m * m != key.Count)
                throw new InvalidAnlysisException();
            //transform the key into 2D Matrix
            List<List<int>> keyMatrix = new List<List<int>>(m);
            for(int i = 0; i < m; i++){
                keyMatrix.Add(new List<int>());
            }

            for(int i = 0; i < m; i++){
                for(int j = 0; j < m; j++){
                    keyMatrix[i].Add(key[i * m + j]);
                }
            }
            ///assert that plainText size is divisble by m to be able to make Lists
            List<int> cipherText = new List<int>();
            for(int i = 0; i < plainText.Count; i += m)
            {
                List<List<int>> curPart = new List<List<int>>();
                for(int j = 0; j < m; j++)
                {
                    curPart.Add(new List<int>());
                    if (i + j < plainText.Count)
                        curPart[j].Add(plainText[i + j]);
                    else
                        curPart[j].Add(0);
                }
                List<int> append = matrixMul(keyMatrix, curPart);
                for(int j = 0; j < m && i + j < plainText.Count; j++)
                {
                    cipherText.Add(append[j]);
                }
            }

            return cipherText;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            if (plainText.Count != cipherText.Count)
                throw new InvalidAnlysisException();
            List<int> Key = new List<int>(3 * 3);
            bool f = false;
            for (int i = 0; i < cipherText.Count; i += 3)
            {
                if (i + 2 > cipherText.Count) break;
                List<int> plainPart = new List<int>(3);
                List<List<int>> cipherPart = new List<List<int>>(3);
                for (int j = 0; j < 3; j++)
                {
                    cipherPart[j] = new List<int>(1);
                    cipherPart[j][0] = cipherText[i + j];
                    plainPart[j] = plainText[i + j];
                }
                ///ct = key * pt
                ///key = ct * pt^-1
                List<List<int>> plainInversion = getInverseion(plainPart);
                List<int> append = matrixMul(cipherPart, plainInversion);
                if (!f)
                {
                    Key = append;
                }
                else
                {
                    for (int x = 0; x < 9; x++)
                        if (Key[x] != append[x])
                            throw new InvalidAnlysisException();
                }
            }
            return Key;
        }

    }
}
