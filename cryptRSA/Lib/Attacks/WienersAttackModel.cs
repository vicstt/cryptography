using System.Collections.Generic;
using System.Numerics;
using cryptRSA.Lib.Attacks;

namespace cryptRSA.Lib.Attacks
{
    /// <summary>
    /// Модель результата атаки Винера.
    /// </summary>
    public class WienersAttackModel
    {
        public BigInteger FoundPrivateKeyExponent { get; set; } = -1;
        public BigInteger FoundEulerPhi { get; set; } = -1;
        public List<ContinuedFraction> CalculatedFractions { get; set; } = new List<ContinuedFraction>();
    }
}