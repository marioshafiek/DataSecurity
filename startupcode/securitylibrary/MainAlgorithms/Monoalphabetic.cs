using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            int length = plainText.Length;
            char[] keyMap = new char[26];
            int[] usedChars = new int[30];
            for (int i = 0; i < 26; i++)
            {
                keyMap[i] = '*';
                usedChars[i] = 0;
            }
            for (int i = 0; i < length; i++)
            {
                int index = plainText[i] - 'a';
                keyMap[index] = cipherText[i];
                usedChars[cipherText[i] - 'A'] = 1;
            }
            string key = "";
            string unUsedChars = "";
            for (int i = 0; i < 26; i++)
            {
                if (usedChars[i] == 0)
                {
                    unUsedChars += (char)(i + 'a');
                }
            }
            int unUsedCharsIndex = 0;
            for (int i = 0; i < 26; i++)
            {
                if (keyMap[i] != '*')
                {
                    key += keyMap[i];
                }
                else
                {
                    key += unUsedChars[unUsedCharsIndex];
                    unUsedCharsIndex++;
                }

            }

            return key.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            char[] keyMap = new char[26];
            int index = 0;
            cipherText = cipherText.ToLower();
            foreach(char ch in key)
            {
                keyMap[index] = ch;
                index++;
            }
            string decrypt= "";
            foreach(char ch in cipherText)
            {
                for(int i=0; i<26;i++)
                {
                    
                    if(ch.Equals(key[i]))
                    {
                        
                        char value = (char)(65 + i);
                        decrypt+=value;
                    }
                }
                
            }

            return decrypt;


        }

        public string Encrypt(string plainText, string key)
        {
            char[] keyMap = new char[26];
            int index = 0;
            foreach (char ch in key)
            {
                keyMap[index] = ch;
                index++;
            }
            string cipher = "";
            
            foreach (char ch in plainText)
            {
                char newChar = (char)(keyMap[(ch - 'a')]);
                cipher += newChar;
            }
            return cipher;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        
        public string AnalyseUsingCharFrequency(string cipher)
        {
            //throw new NotImplementedException();

            string frequency = "zqjxkvbywgpfmucdlhrsnioate";


            cipher = cipher.ToLower();

            //dictonary for counter
            Dictionary<char, int> counting = new Dictionary<char, int>();

            //dictonary for keys
            Dictionary<char, char> keys = new Dictionary<char, char>();

          
            for (int i = 0; i < cipher.Length; i++)
            {
                if (!counting.ContainsKey(cipher[i]))
                {
                    counting[cipher[i]] = 0;
                }
                counting[cipher[i]]++;
            }

            int it = 0;
           

            foreach (KeyValuePair<char, int> item in counting.OrderBy(key => key.Value))
            {
                keys[item.Key] = frequency[it];
                it++;
            }

            string final = string.Empty;

            for (int i = 0; i < cipher.Length; i++)
            {
                final += keys[cipher[i]];
            }
            return final;
        }
    }
}

    

