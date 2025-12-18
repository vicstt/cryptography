using System.Numerics;

namespace cryptRSA.Lib.Interfaces
{
    /// <summary>
    /// Интерфейс для базовых математических операций.
    /// </summary>
    public interface IMath
    {
        /// <summary>
        /// Вычисляет символ Лежандра (a|p).
        /// </summary>
        int LegendreSymbol(BigInteger a, BigInteger p);

        /// <summary>
        /// Вычисляет символ Якоби (a|n).
        /// </summary>
        int JacobiSymbol(BigInteger a, BigInteger n);

        /// <summary>
        /// Вычисляет НОД двух чисел.
        /// </summary>
        BigInteger Gcd(BigInteger a, BigInteger b);

        /// <summary>
        /// Расширенный алгоритм Евклида.
        /// </summary>
        (BigInteger gcd, BigInteger x, BigInteger y) ExtendedGcd(BigInteger a, BigInteger b);

        /// <summary>
        /// Выполняет возведение в степень по модулю.
        /// </summary>
        BigInteger ModPow(BigInteger baseValue, BigInteger exponent, BigInteger modulus);
    }
}