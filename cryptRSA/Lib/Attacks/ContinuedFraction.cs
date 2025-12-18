using System.Numerics;

namespace cryptRSA.Lib.Attacks
{
    /// <summary>
    /// Модель для хранения числителя и знаменателя подходящей дроби.
    /// </summary>
    public class ContinuedFraction
    {
        public BigInteger Numerator { get; }
        public BigInteger Denominator { get; }

        public ContinuedFraction(BigInteger numerator, BigInteger denominator)
        {
            Numerator = numerator;
            Denominator = denominator;
        }

        public override string ToString()
        {
            return $"({Numerator}/{Denominator})";
        }
    }
}