using System;

namespace Lib.Crypto
{
    public class PKCS7Padding : IPadding
    {
        public byte[] Pad(byte[] data, int blockSize)
        {
            int paddingLength = blockSize - (data.Length % blockSize);
            if (paddingLength == 0) paddingLength = blockSize;
            
            byte[] result = new byte[data.Length + paddingLength];
            Array.Copy(data, result, data.Length);
            
            for (int i = data.Length; i < result.Length; i++)
                result[i] = (byte)paddingLength;
            
            return result;
        }
        
        public byte[] Unpad(byte[] data)
        {
            if (data.Length == 0) return data;
            
            int paddingLength = data[data.Length - 1];
            if (paddingLength <= 0 || paddingLength > data.Length)
                throw new ArgumentException("Некорректное заполнение PKCS7");
            
            for (int i = data.Length - paddingLength; i < data.Length; i++)
                if (data[i] != paddingLength)
                    throw new ArgumentException("Некорректное заполнение PKCS7");
            
            byte[] result = new byte[data.Length - paddingLength];
            Array.Copy(data, result, result.Length);
            return result;
        }
    }
    
    public class ZeroPadding : IPadding
    {
        public byte[] Pad(byte[] data, int blockSize)
        {
            int paddingLength = blockSize - (data.Length % blockSize);
            if (paddingLength == blockSize) return data;
            
            byte[] result = new byte[data.Length + paddingLength];
            Array.Copy(data, result, data.Length);
            return result;
        }
        
        public byte[] Unpad(byte[] data)
        {
            int lastNonZero = data.Length - 1;
            while (lastNonZero >= 0 && data[lastNonZero] == 0)
                lastNonZero--;
            
            byte[] result = new byte[lastNonZero + 1];
            Array.Copy(data, result, result.Length);
            return result;
        }
    }
}