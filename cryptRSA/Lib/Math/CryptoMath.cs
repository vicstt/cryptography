using System.Numerics;
using cryptRSA.Lib.Interfaces;

namespace cryptRSA.Lib.Math
{
    /// <summary>
    /// Реализация IMath.
    /// </summary>
    public class CryptoMath : IMath
    {
        public int LegendreSymbol(BigInteger a, BigInteger p)
        {
            if (p <= 1) throw new System.ArgumentException("p must be > 1.");
            
            var result = ModPow(a, (p - 1) / 2, p);
            return result == 1 ? 1 : (result == p - 1 ? -1 : 0);
        }

        public int JacobiSymbol(BigInteger a, BigInteger n)
        {
            if (n <= 0 || n.IsEven) 
                throw new System.ArgumentException("n must be a positive odd integer.");
            
            a = a % n;
            int result = 1;
            int iterations = 0;
            const int maxIterations = 1000;
            
            while (a != 0 && iterations < maxIterations)
            {
                iterations++;
                
                while (a.IsEven)
                {
                    a /= 2;
                    var nMod8 = n % 8;
                    if (nMod8 == 3 || nMod8 == 5) result = -result;
                }
                
                (a, n) = (n, a);
                
                if (a % 4 == 3 && n % 4 == 3) 
                    result = -result;
                
                a = a % n;
            }
            
            if (iterations >= maxIterations)
                throw new InvalidOperationException("JacobiSymbol: слишком много итераций");
            
            return n == 1 ? result : 0;
        }

        public BigInteger Gcd(BigInteger a, BigInteger b)
        {
            a = BigInteger.Abs(a);
            b = BigInteger.Abs(b);
            while (b != 0)
            {
                var temp = b;
                b = a % b;
                a = temp;
            }
            return a;
        }

        public (BigInteger gcd, BigInteger x, BigInteger y) ExtendedGcd(BigInteger a, BigInteger b)
        {
            BigInteger old_r = a; BigInteger r = b;
            BigInteger old_s = 1;  BigInteger s = 0;
            BigInteger old_t = 0;  BigInteger t = 1;

            while (r != 0)
            {
                var quotient = old_r / r;
                (old_r, r) = (r, old_r - quotient * r);
                (old_s, s) = (s, old_s - quotient * s);
                (old_t, t) = (t, old_t - quotient * t);
            }
            return (old_r, old_s, old_t);
        }

        public BigInteger ModPow(BigInteger baseValue, BigInteger exponent, BigInteger modulus)
        {
            if (modulus == 1) return 0;
            BigInteger result = 1;
            baseValue = baseValue % modulus;
            while (exponent > 0)
            {
                if (!exponent.IsEven) result = (result * baseValue) % modulus;
                exponent >>= 1;
                baseValue = (baseValue * baseValue) % modulus;
            }
            return result;
        }
    }
}