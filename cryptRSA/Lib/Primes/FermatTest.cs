using System;
using System.Numerics;
using cryptRSA.Lib.Interfaces;
using static System.Math;

namespace cryptRSA.Lib.Primes
{
    /// <summary>
    /// Реализация теста Ферма.
    /// </summary>
    public class FermatTest : PrimalityTest
    {
        private readonly Random _random = new Random();

        public FermatTest(IMath mathService) : base(mathService) { }

        protected override bool RunSingleTest(BigInteger candidate)
        {
            if (candidate < 2) return false;
            if (candidate == 2 || candidate == 3) return true;
            if (candidate.IsEven) return false;

            if (candidate < 1000)
            {
                return IsSmallPrime(candidate);
            }

            BigInteger a;
            try
            {
                a = GenerateRandomBigInteger(2, candidate - 2);
            }
            catch
            {
                return false;
            }

            return _mathService.ModPow(a, candidate - 1, candidate) == 1;
        }

        protected override int CalculateIterations(double minProbability)
        {
            return (int)Ceiling(-Log2(1.0 - minProbability));
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

        private bool IsSmallPrime(BigInteger n)
        {
            if (n < 2) return false;
            if (n == 2 || n == 3) return true;
            if (n.IsEven) return false;

            for (int i = 3; i * i <= n && i < 1000; i += 2)
            {
                if (n % i == 0) return false;
            }
            return true;
        }
    }
}