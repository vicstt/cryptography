using System.Numerics;
using cryptRSA.Lib.Interfaces;

namespace cryptRSA.Lib.Primes
{
    /// <summary>
    /// Абстрактный базовый класс для вероятностных тестов простоты.
    /// </summary>
    public abstract class PrimalityTest : IPrimalityTests
    {
        protected readonly IMath _mathService;

        protected PrimalityTest(IMath mathService)
        {
            _mathService = mathService;
        }

        public bool IsPrime(BigInteger candidate, double minProbability)
        {
            if (candidate < 2) return false;
            if (candidate == 2) return true;
            if (candidate.IsEven) return false;

            int iterations = CalculateIterations(minProbability);
            for (int i = 0; i < iterations; i++)
            {
                if (!RunSingleTest(candidate))
                    return false;
            }
            return true;
        }

        protected abstract bool RunSingleTest(BigInteger candidate);
        protected abstract int CalculateIterations(double minProbability);
    }
}