using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            
            double plainSize = plainText.Length;
            cipherText = cipherText.ToLower();
            SortedDictionary<int, int> sortDic = new SortedDictionary<int, int>();

            for (int k = 1; k < Int32.MaxValue; k++)
            {
                int count = 0;
                double w = k;
                double h = Math.Ceiling(plainSize / k); ;
                string[,] pl = new string[(int)h, (int)w];
                for (int i = 0; i < h; i++)
                {
                    for (int j = 0; j < k; j++)
                    {
                        if (count >= plainSize)
                        {
                            pl[i, j] = "";
                        }
                        else
                        {
                            pl[i, j] = plainText[count].ToString();

                            count++;
                        }
                    }
                }
                
                List<string> Clist = new List<string>();
                for (int i = 0; i < k; i++)
                {
                    string word = "";
                    for (int j = 0; j < h; j++)
                    {
                        word += pl[j, i];
                    }
                    Clist.Add(word);
                }

                if (Clist.Count == 7)
                {
                    string d = "";
                }

                bool corrkey = true;
                string cipherC = (string)cipherText.Clone();
             
                sortDic = new SortedDictionary<int, int>();
                for (int i = 0; i < Clist.Count; i++)
                {
                   
                    int x = cipherC.IndexOf(Clist[i]);
                    if (x == -1)
                    {
                        corrkey = false;
                    }
                    else
                    {
                        sortDic.Add(x, i + 1);
                        cipherC.Replace(Clist[i], "#");
                    }

                }
                if (corrkey)
                    break;

            }
            

            Dictionary<int, int> DictionNew = new Dictionary<int, int>();
            List<int> keyOutput = new List<int>();



            for (int j = 0; j < sortDic.Count; j++)
            {
                DictionNew.Add(sortDic.ElementAt(j).Value, j + 1);
            }

            for (int k = 1; k < DictionNew.Count + 1; k++)
            {
                keyOutput.Add(DictionNew[k]);
            }
            
            return keyOutput;

        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int keyCount = key.Count;
            string plainText = "";
            int row = (int)Math.Ceiling(Decimal.Divide(cipherText.Length, keyCount));
            char[,] plaintMatrix = new char[row, key.Count];
            int searchIndex = 1;
            for (int j = 0, k = 0; j < key.Count; j++)
            {
                for (int m = 0; m < key.Count; m++)
                {
                    if (key[m] == searchIndex)
                    {
                        for (int i = 0; i < row; i++)
                        {
                            if (cipherText.Length > k)
                            {
                                plaintMatrix[i, m] = cipherText[k];
                            }
                            k++;
                        }
                    }
                }
                searchIndex++;
            }


            for (int i = 0, k = 0; i < row; i++)
            {
                for (int j = 0; j < keyCount; j++)
                {
                    if (k >= cipherText.Length)
                    {
                        break;
                    }
                    else
                    {
                        plainText += plaintMatrix[i, j].ToString();
                    }
                    k++;
                }
            }

            return plainText;

        }

        public string Encrypt(string plainText, List<int> key)
        {
            int keyCount = key.Count;
            string cipher = "";
            int row = (int)Math.Ceiling(Decimal.Divide(plainText.Length, keyCount));

            char[,] CipherMatrix = new char[row, keyCount];
            for (int i = 0, k = 0; i < row; i++)
            {
                for (int j = 0; j < keyCount; j++)
                {
                    if (k >= plainText.Length)
                    {
                        CipherMatrix[i, j] = '\0';
                    }
                    else
                    {
                        CipherMatrix[i, j] = plainText[k];
                    }
                    k++;
                }
            }

            int searchIndex = 1;
            for (int i = 0; i < keyCount; i++)
            {
                for (int j = 0; j < keyCount; j++)
                {
                    if (key[j] == searchIndex)
                    {
                        for (int k = 0; k < row; k++)
                        {
                            if (CipherMatrix[k, j] != '\0')
                            {
                                cipher += CipherMatrix[k, j].ToString();
                            }

                        }
                        break;
                    }
                }
                searchIndex++;
            }
            cipher = cipher.ToUpper();
            return cipher;
        }
    }
}
