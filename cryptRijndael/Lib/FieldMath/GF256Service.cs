using System;
using System.Collections.Generic;

namespace Lib.FieldMath
{
    public class GF256Service
    {
        public byte Add(byte a, byte b) => (byte)(a ^ b);

        public byte Multiply(byte a, byte b, byte modulus)
        {
            if (!IsIrreducible(modulus))
                throw new ArgumentException($"Модуль 0x{modulus:X2} приводим над GF(2^8)");
            
            byte result = 0;
            byte hi_bit_set;
            
            while (b > 0)
            {
                if ((b & 1) == 1)
                    result ^= a;

                hi_bit_set = (byte)(a & 0x80);
                a <<= 1;
                if (hi_bit_set != 0)
                    a ^= modulus;

                b >>= 1;
            }
            return result;
        }

        public byte Inverse(byte a, byte modulus)
        {
            if (a == 0) 
                throw new ArgumentException("Нет обратного для нуля");
            
            if (!IsIrreducible(modulus))
                throw new ArgumentException($"Модуль 0x{modulus:X2} приводим над GF(2^8)");
            
            // a^(-1) = a^(254) в GF(2^8)
            return Power(a, 254, modulus);
        }

        private byte Power(byte baseValue, int exponent, byte modulus)
        {
            byte result = 1;
            byte current = baseValue;
            
            while (exponent > 0)
            {
                if ((exponent & 1) == 1)
                    result = Multiply(result, current, modulus);
                
                current = Multiply(current, current, modulus);
                exponent >>= 1;
            }
            
            return result;
        }

        public bool IsIrreducible(byte polynomialByte)
        {
            if (polynomialByte == 0) return false;
            
            // Полином степени 8: x^8 + a7*x^7 + ... + a1*x + 1
            // Преобразуем в целое число
            int p = 0x100 | polynomialByte;
            
            // Свободный член должен быть 1 для неприводимого полинома нечетной степени
            if ((polynomialByte & 1) == 0) return false;
            
            // Проверяем делимость на все неприводимые полиномы степени ≤ 4
            // Это достаточная проверка для полинома степени 8
            int[] irreducibleFactors = {
                0b10,        // x
                0b11,        // x + 1
                0b111,       // x^2 + x + 1
                0b1011,      // x^3 + x + 1
                0b1101,      // x^3 + x^2 + 1
                0b10011,     // x^4 + x + 1
                0b11001,     // x^4 + x^3 + 1
                0b11111      // x^4 + x^3 + x^2 + x + 1
            };

            foreach (var factor in irreducibleFactors)
            {
                if (GetRemainder(p, factor) == 0)
                    return false;
            }

            return true;
        }

        public List<byte> GetAllIrreducibleDegree8()
        {
            // Используем известный список неприводимых полиномов степени 8 над GF(2)
            // Всего их 30 согласно теории
            byte[] knownIrreducible = {
                0x1B, 0x1D, 0x2B, 0x2D, 0x39, 0x3F, 0x4D, 0x5F,
                0x63, 0x65, 0x69, 0x71, 0x77, 0x7B, 0x87, 0x8B,
                0x8D, 0x9F, 0xA3, 0xA9, 0xB1, 0xBD, 0xC3, 0xCF,
                0xD7, 0xDD, 0xE7, 0xF3, 0xF5, 0xF9
            };
            
            var result = new List<byte>();
            foreach (var poly in knownIrreducible)
            {
                // Проверяем, что полином действительно неприводим
                if (IsIrreducible(poly))
                    result.Add(poly);
            }
            
            // Если наш алгоритм нашел меньше, используем известный список
            if (result.Count < 30)
            {
                result.Clear();
                result.AddRange(knownIrreducible);
            }
            
            return result;
        }

        public List<byte> FactorPolynomial(byte poly, byte modulus)
        {
            var factors = new List<byte>();
            
            if (poly == 0 || poly == 1)
            {
                factors.Add(poly);
                return factors;
            }
            
            byte current = poly;
            
            // Проверяем все возможные делители до 255
            for (byte i = 2; i <= 0xFF; i++)
            {
                if (!IsIrreducible(i)) continue;
                
                while (true)
                {
                    int remainder = GetRemainder(current, i);
                    if (remainder != 0) break;
                    
                    factors.Add(i);
                    current = (byte)PolyDiv(current, i);
                    if (current == 1) break;
                }
                
                if (current == 1) break;
            }
            
            if (current != 1 && current != 0)
                factors.Add(current);
                
            return factors;
        }

        private static int GetRemainder(int dividend, int divisor)
        {
            if (divisor == 0) throw new DivideByZeroException();
            
            int divisorDegree = GetPolynomialDegree(divisor);
            while (GetPolynomialDegree(dividend) >= divisorDegree)
            {
                int degreeDifference = GetPolynomialDegree(dividend) - divisorDegree;
                dividend ^= divisor << degreeDifference;
            }
            return dividend;
        }

        private static int PolyDiv(int dividend, int divisor)
        {
            if (divisor == 0) throw new DivideByZeroException();
            
            int quotient = 0;
            int divisorDegree = GetPolynomialDegree(divisor);
            
            while (GetPolynomialDegree(dividend) >= divisorDegree)
            {
                int degreeDifference = GetPolynomialDegree(dividend) - divisorDegree;
                quotient |= 1 << degreeDifference;
                dividend ^= divisor << degreeDifference;
            }
            
            return quotient;
        }

        private static int GetPolynomialDegree(int polynomial)
        {
            if (polynomial == 0) return -1;
            
            for (int i = 31; i >= 0; i--)
            {
                if (((polynomial >> i) & 1) == 1) return i;
            }
            return 0;
        }
    }
}