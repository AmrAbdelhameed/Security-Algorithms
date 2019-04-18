using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> result = new List<int>();
            int ya = pow(alpha, xa, q);
            int yb = pow(alpha, xb, q);
            int k1 = pow(yb, xa, q);
            int k2 = pow(ya, xb, q);
            result.Add(k1);
            result.Add(k2);
            return result;
        }

        public int pow(int a, int b, int c)
        {
            int res = 1;
            for (int i = 0; i < b; i++)
                res = (res * a) % c;
            return res;
        }
    }
}
