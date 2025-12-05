using System;
using cryptDES.Lib.Feistel;
using cryptDES.Lib.Interfaces;

namespace cryptDES.Lib.DEAL
{
    public class DEALAlgorithm : FeistelNetwork
    {
        public DEALAlgorithm(int keySizeInBytes) : base(
            new DEALKeyScheduler(keySizeInBytes), 
            new DESAdapter(), 16, 16) {}

        public DEALAlgorithm() : this(16) { } 

        public DEALAlgorithm(DEALKeyScheduler.KeySize keySize) : this((int)keySize) { }
    }
}