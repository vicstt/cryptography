using System;
using System.Numerics;
using cryptRSA.Lib.Interfaces;
using static System.Math; 

namespace cryptRSA.Lib.Primes
{
    public class MillerRabinTest : PrimalityTest
    {
        private readonly Random _random = new Random();

        public MillerRabinTest(IMath mathService) : base(mathService) { }

        protected override bool RunSingleTest(BigInteger candidate)
        {
            BigInteger d = candidate - 1;
            int r = 0;
            while (d.IsEven)
            {
                d >>= 1;
                r++;
            }

            BigInteger a = GenerateRandomBigInteger(2, candidate - 2);
            var x = _mathService.ModPow(a, d, candidate);

            if (x == 1 || x == candidate - 1) return true;

            for (int i = 0; i < r - 1; i++)
            {
                x = _mathService.ModPow(x, 2, candidate);
                if (x == candidate - 1) return true;
            }
            return false;
        }

        protected override int CalculateIterations(double minProbability)
        {
            return (int)Ceiling(-Log(1.0 - minProbability, 4));
        }

        private BigInteger GenerateRandomBigInteger(BigInteger min, BigInteger max)
        {
            var bytes = max.ToByteArray();
            BigInteger randomValue;
            do
            {
                var randomBytes = new byte[bytes.Length];
                _random.NextBytes(randomBytes);
                randomBytes[randomBytes.Length - 1] &= (byte)0x7F;
                randomValue = new BigInteger(randomBytes);
            } while (randomValue < min || randomValue > max);
            return randomValue;
        }
    }
}