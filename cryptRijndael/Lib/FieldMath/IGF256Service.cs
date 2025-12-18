using System.Collections.Generic;

namespace Lib.FieldMath
{
    public interface IGF256Service
    {
        byte Add(byte a, byte b);
        byte Multiply(byte a, byte b, ushort modulus);
        byte Inverse(byte a, ushort modulus);
        bool IsIrreducible(ushort poly);
        List<ushort> GetAllIrreducibleDegree8();
        List<ushort> FactorPolynomial(ushort poly, ushort modulus);
    }
}