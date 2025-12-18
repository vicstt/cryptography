using System;
using System.Collections.Generic;
using System.Numerics;
using cryptRSA.Lib.Interfaces;
using cryptRSA.Lib.RSA.Models;

namespace cryptRSA.Lib.Attacks
{
    /// <summary>
    /// Сервис для выполнения атаки Винера на открытый ключ RSA.
    /// </summary>
    public class WienersAttack : IWienersAttack
    {
        private readonly IMath _mathService;

        public WienersAttack(IMath mathService)
        {
            _mathService = mathService;
        }

        public WienersAttackModel PerformAttack(PublicKey publicKey)
        {
            var result = new WienersAttackModel();
            var e = publicKey.Exponent;
            var n = publicKey.Modulus;

            var coefficients = GetContinuedFractionCoefficients(e, n);
            var convergents = new List<ContinuedFraction>();

            for (int i = 0; i < coefficients.Count; i++)
            {
                var (numerator, denominator) = CalculateConvergent(coefficients, i);
                if (denominator == 0) continue;
                convergents.Add(new ContinuedFraction(numerator, denominator));
            }

            result.CalculatedFractions = convergents;

            foreach (var fraction in convergents)
            {
                var k = fraction.Numerator;
                var d = fraction.Denominator;

                if (k == 0 || d == 0) continue;

                if ((e * d - 1) % k != 0)
                    continue;

                var phi = (e * d - 1) / k;

                var s = n - phi + 1;
                var discriminant = s * s - 4 * n;
                if (discriminant < 0) continue;

                var sqrtDiscriminant = Sqrt(discriminant);
                if (sqrtDiscriminant * sqrtDiscriminant != discriminant) continue;

                var p = (s + sqrtDiscriminant) / 2;
                var q = (s - sqrtDiscriminant) / 2;

                if (p > 1 && q > 1 && p * q == n)
                {
                    result.FoundPrivateKeyExponent = d;
                    result.FoundEulerPhi = phi;
                    return result;
                }
            }

            return result; 
        }

        private List<int> GetContinuedFractionCoefficients(BigInteger a, BigInteger b)
        {
            var coefficients = new List<int>();
            while (b != 0)
            {
                var quotient = a / b;
                
                if (quotient > int.MaxValue)
                {
                    coefficients.Add(int.MaxValue);
                }
                else if (quotient < int.MinValue)
                {
                    coefficients.Add(int.MinValue);
                }
                else
                {
                    coefficients.Add((int)quotient);
                }
                
                var temp = a % b;
                a = b;
                b = temp;
            }
            return coefficients;
        }

        private (BigInteger, BigInteger) CalculateConvergent(List<int> coefficients, int index)
        {
            if (index >= coefficients.Count) return (0, 0);
            if (index == 0)
                return (coefficients[0], 1);

            BigInteger hPrev2 = 0, hPrev1 = 1;
            BigInteger kPrev2 = 1, kPrev1 = 0;

            for (int i = 0; i <= index; i++)
            {
                var h_n = coefficients[i] * hPrev1 + hPrev2;
                var k_n = coefficients[i] * kPrev1 + kPrev2;

                hPrev2 = hPrev1;
                hPrev1 = h_n;
                kPrev2 = kPrev1;
                kPrev1 = k_n;
            }

            return (hPrev1, kPrev1);
        }

        private BigInteger Sqrt(BigInteger n)
        {
            if (n < 0) return 0;
            if (n == 0) return 0;
            
            BigInteger x = n;
            BigInteger y = (n + 1) / 2;
            while (y < x)
            {
                x = y;
                y = (x + n / x) / 2;
            }
            return x;
        }
    }
}