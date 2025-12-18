using System.Numerics;

namespace cryptRSA.Lib.Interfaces
{
    /// <summary>
    /// Интерфейс для вероятностного теста простоты.
    /// </summary>
    public interface IPrimalityTests
    {
        /// <summary>
        /// Проверяет, является ли число вероятно простым.
        /// </summary>
        bool IsPrime(BigInteger candidate, double minProbability);
    }
}