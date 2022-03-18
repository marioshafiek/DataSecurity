using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }   

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string alpha = "abcdefghijklmnopqrstuvwxyz";
        public int[] check_alpha = new int[26];
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            char[,] arr1 = new char[5, 5];

            string b = "";

            for (int i = 0; i < 25; i++)
                check_alpha[i] = 0;
            int z = 5;
            int y = 5;

            for (int k = 0; k < z; k++)
            {
                for (int x = 0; x < y; x++)
                    arr1[k, x] = '\0';

            }

            int exist;
            int keyy = 0;
            int alphabitics = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    exist = 0;
                    for (int k = keyy; k < key.Length; k++)
                    {

                        if (check_alpha[((key[k] - 97) % alpha.Length)] == 0)
                        {
                            arr1[i, j] = key[k];
                            check_alpha[((key[k] - 97) % alpha.Length)] = 1;
                            exist = 1;

                        }
                        if (exist == 1)
                            break;
                    }

                    if (exist == 0)
                    {
                        for (int k = alphabitics; k < alpha.Length; k++)
                        {


                            if (check_alpha[((alpha[k] - 97) % alpha.Length)] == 0)
                            {
                                if (alpha[k] != 'j')
                                {

                                    arr1[i, j] = (char)(k + 97);
                                    check_alpha[((alpha[k] - 97) % alpha.Length)] = 1;
                                    alphabitics++;
                                    break;
                                }
                                if (alpha[k] == 'j')
                                    alphabitics++;

                            }
                        }
                    }


                    keyy++;
                }
            }
            for (int i = 0; i < cipherText.Length; i += 2)
            {

                char decchar1;
                char decchar2;


                int[] place = new int[4];
                for (int r = 0; r < 4; r++)
                {
                    place[r] = 0;
                }
                for (int r = 0; r < 5; r++)
                {
                    for (int a = 0; a < 5; a++)
                    {
                        if (arr1[r, a] == cipherText[i])
                        {
                            place[0] = r; place[1] = a;
                        }
                        if (arr1[r, a] == cipherText[i + 1])
                        {
                            place[2] = r; place[3] = a;
                        }
                    }
                }
                if (place[0] == place[2])
                {
                    int col1 = (place[1] - 1) % 5;
                    int col2 = (place[3] - 1) % 5;
                    if (col1 < 0) col1 += 5;
                    if (col2 < 0) col2 += 5;
                    decchar1 = arr1[place[0], col1];
                    decchar2 = arr1[place[2], col2];

                    //same row
                }
                else if (place[1] == place[3])
                {
                    int row1 = (place[0] - 1) % 5;
                    int row2 = (place[2] - 1) % 5;
                    if (row1 < 0) row1 += 5;
                    if (row2 < 0) row2 += 5;
                    decchar1 = arr1[row1, place[1]];
                    decchar2 = arr1[row2, place[3]];
                    //same column
                }
                else
                {
                    decchar1 = arr1[(place[0]), (place[3])];
                    decchar2 = arr1[(place[2]), (place[1])];
                    //diagonal
                }


                b += decchar1;
                b += decchar2;

            }
            string v = b.Substring(0, 1);
            for (int i = 1; i < b.Length - 1; i++)
            {
                if (!(b[i] == 'x' && b[i - 1] == b[i + 1] && i % 2 != 0))
                {
                    v += b.Substring(i, 1);
                }
            }
            if (b[b.Length - 1] != 'x')
            {
                v += b.Substring(b.Length - 1, 1);
            }
            v = v.ToUpper();
            return v;
        }



        public string Encrypt(string plainText, string key)
        {

            plainText = plainText.ToLower();
            char[,] arr1 = new char[5, 5];

            string b = "";

            for (int i = 0; i < 25; i++)
                check_alpha[i] = 0;
            int z = 5;
            int y = 5;

            for (int k = 0; k < z; k++)
            {
                for (int x = 0; x < y; x++)
                    arr1[k, x] = '\0';

            }

            int exist;
            int keyy = 0;
            int alphabitics = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    exist = 0;
                    for (int k = keyy; k < key.Length; k++)
                    {

                        if (check_alpha[((key[k] - 97) % alpha.Length)] == 0)
                        {
                            arr1[i, j] = key[k];
                            check_alpha[((key[k] - 97) % alpha.Length)] = 1;
                            exist = 1;

                        }
                        if (exist == 1)
                            break;
                    }

                    if (exist == 0)
                    {
                        for (int k = alphabitics; k < alpha.Length; k++)
                        {


                            if (check_alpha[((alpha[k] - 97) % alpha.Length)] == 0)
                            {
                                if (alpha[k] != 'j')
                                {

                                    arr1[i, j] = (char)(k + 97);
                                    check_alpha[((alpha[k] - 97) % alpha.Length)] = 1;
                                    alphabitics++;
                                    break;
                                }
                                if (alpha[k] == 'j')
                                    alphabitics++;

                            }
                        }
                    }


                    keyy++;
                }
            }

            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Insert(i + 1, "x");
                }

            }
            if (plainText.Length % 2 != 0)
            {
                plainText = plainText + 'x';
            }

            for (int i = 0; i < plainText.Length; i += 2)
            {

                char decchar1;
                char decchar2;


                int[] place = new int[4];
                for (int r = 0; r < 4; r++)
                {
                    place[r] = 0;
                }
                for (int r = 0; r < 5; r++)
                {
                    for (int a = 0; a < 5; a++)
                    {
                        if (arr1[r, a] == plainText[i])
                        {
                            place[0] = r; place[1] = a;
                        }
                        if (arr1[r, a] == plainText[i + 1])
                        {
                            place[2] = r; place[3] = a;
                        }
                    }
                }
                if (place[0] == place[2])
                {
                    int col1 = (place[1] + 1) % 5;
                    int col2 = (place[3] + 1) % 5;

                    decchar1 = arr1[place[0], col1];
                    decchar2 = arr1[place[2], col2];

                    //same row
                }
                else if (place[1] == place[3])
                {
                    int row1 = (place[0] + 1) % 5;
                    int row2 = (place[2] + 1) % 5;

                    decchar1 = arr1[row1, place[1]];
                    decchar2 = arr1[row2, place[3]];
                    //same column
                }
                else
                {
                    decchar1 = arr1[(place[0]), (place[3])];
                    decchar2 = arr1[(place[2]), (place[1])];
                    //diagonal
                }


                b += decchar1;
                b += decchar2;

            }

            b = b.ToUpper();
            return b;
        }

    }
}
