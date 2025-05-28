//author: Griffin Danner-Doran
//This file contains the PrimeChecker class, a helper class that provides the Miller-Rabin algorithm extension method
//used to test candidate primes in the PrimeGenerator class.

using System.Numerics;
using System.Security.Cryptography;

namespace PrimeFinder;

/// <summary>
/// The PrimeChecker class contains the IsProbablyPrime method, which is used to test if a candidate is actually prime.
/// </summary>
public static class PrimeChecker
{
    /// <summary>
    /// This method checks if the provided BigInteger is a prime using the Miller-Rabin primality test repeated over
    /// the provided number of rounds(default 10).
    /// </summary>
    /// <param name="value">The BigInteger prime candidate to analyze for primality.</param>
    /// <param name="k">The number of rounds to repeat the MR algorithm over, defaults to 10.</param>
    /// <returns> True if the candidate is prime, False if not.</returns>
    public static Boolean IsProbablyPrime(this BigInteger value, int k = 10)
    {
        BigInteger s = 0;
        var d = value - 1;
        while (d % 2 != 1) //take out factors of 2 until we have an odd factor
        {
            s++;
            d /= 2;
        }

        BigInteger x;
        BigInteger y = 0;
        for (BigInteger i = 0; i < k; i++)
        {
            var size = value.GetByteCount();
            BigInteger a;
            //generates random BigIntegers 1 byte smaller than value until we get one in the target range of (2,value-2)
            do
            {
                a = BigInteger.Abs(new BigInteger(RandomNumberGenerator.GetBytes(size - 1)));
            } while (a > value - 2 || a < 2);

            x = BigInteger.ModPow(a, d, value);
            for (BigInteger j = 0; j < s; j++)
            {
                y = BigInteger.ModPow(x, 2, value);
                if (y == 1 && x != 1 && x != value - 1)
                {
                    return false;
                }

                x = y;
            }

            if (y != 1)
            {
                return false;
            }
        }

        return true;
    }
}