using System;
using System.Numerics;
using cryptRSA.Lib.Interfaces;
using static System.Math; 

namespace cryptRSA.Lib.Primes
{
    public class SoloveyStrassenTest : PrimalityTest
    {
        private readonly Random _random = new Random();

        public SoloveyStrassenTest(IMath mathService) : base(mathService) { }

        protected override bool RunSingleTest(BigInteger candidate)
        {
            BigInteger a = GenerateRandomBigInteger(2, candidate - 1);
            int jacobi = _mathService.JacobiSymbol(a, candidate);
            if (jacobi == 0) return false;

            var modExp = _mathService.ModPow(a, (candidate - 1) / 2, candidate);
            return modExp == jacobi || modExp == candidate + jacobi;
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
    }
}