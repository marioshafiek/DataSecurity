using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        static string alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        static char[] letter = alpha.ToCharArray(); public string Encrypt(string plainText, int key)
        {
            string x = "";
            char[] PL = plainText.ToUpper().ToCharArray();
            for (int i = 0; i < PL.Length; i++)
            {
                for (int j = 0; j < letter.Length; j++)
                {
                    if (PL[i] == letter[j])
                    {
                        x += letter[(j + key) % 26];
                        break;
                    }
                }
            }
            return x;
        }
        public string Decrypt(string cipherText, int key)
        {
            char[] CT = cipherText.ToUpper().ToCharArray();
            string x = "";
            for (int i = 0; i < CT.Length; i++)
            {
                for (int j = 0; j < letter.Length; j++)
                {
                    if (CT[i] == letter[j])
                    {
                        int res = j - key;
                        if (res < 0)
                            res = res + 26;
                        x += letter[res];
                        break;
                    }
                }
            }
            return x;
        }
        public int Analyse(string plainText, string cipherText)
        {
            char[] CT = cipherText.ToUpper().ToCharArray();
            int cipher = 0;
            int plain = 0; for (int i = 0; i < letter.Length; i++)
            {
                if (CT[0] == letter[i])
                {
                    cipher = i;
                    break;
                }
            }
            char[] PT = plainText.ToUpper().ToCharArray();
            for (int i = 0; i < letter.Length; i++)
            {
                if (PT[0] == letter[i])
                {
                    plain = i;
                    break;
                }
            }
            if (cipher < plain)
                return (cipher - plain) + 26;
            else
                return cipher - plain;
        }
    }
}

