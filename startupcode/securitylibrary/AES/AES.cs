using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>



    public class AES : CryptographicTechnique
    {
                           //0       1       2       3       4        5       6        7      8       9      10       11     12       13      14     15     
        string[,] sBox = {{"63", "7c", "77", "7b", "f2",  "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"},
                          { "ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c","a4", "72", "c0"},
                          { "b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71","d8", "31", "15"},
                          { "04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"},
                          { "09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"},
                          { "53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"},
                          { "d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"},
                          { "51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"},
                          { "cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"},
                          { "60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"},
                          { "e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"},
                          { "e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"},
                          { "ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"},
                          { "70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"},
                          { "e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"},
                          { "8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"}};
        

        //Matrices For CipherText and Key
        string[,] PlainTextMatrix = new string[4,4];
        string[,] CipherKeyMatrix = new string[4, 4];
        string[,] MatrixForMixColumns =
        {
            {"02","03","01","01"},
            {"01","02","03","01"},
            {"01","01","02","03"},
            {"03","01","01","02"}
        };
      
        //This Dictonary To Convert from Hexa To Binary
        public static readonly Dictionary<char, string> hexCharacterToBinary = new Dictionary<char, string>
        {
            //0f5
            //0-->0000
            //f-->1111
            //5-->0101
                { '0', "0000" },
                { '1', "0001" },
                { '2', "0010" },
                { '3', "0011" },
                { '4', "0100" },
                { '5', "0101" },
                { '6', "0110" },
                { '7', "0111" },
                { '8', "1000" },
                { '9', "1001" },
                { 'a', "1010" },
                { 'b', "1011" },
                { 'c', "1100" },
                { 'd', "1101" },
                { 'e', "1110" },
                { 'f', "1111" } 
};

        //Convert From Binary TO HexaDecimal
        string HexConvertedToBinary(string strBinary)
        {
            string strHex = Convert.ToInt32(strBinary, 2).ToString("X");
            return strHex;
        }
        //Convert Matrix from HexaToBinary
        public string[,] ToBinary(string[,] Hexa)
        {
            for(int i=0;i<4;i++)
            {
                for(int j=0;j<4;j++)
                {
                    string s = Hexa[i,j];
                    string a = hexCharacterToBinary[s[0]];
                    string b = hexCharacterToBinary[s[1]];
                    string sum = a + b;
                    Hexa[i,j] = sum;
                }
            }
            return Hexa;
        }
        //Conver Matrix from BinaryToHexa
        public string[,] ToHexa(string[,] Binary)
        {
            for(int i=0; i<4;i++)
            {
                for(int j=0;j<4;j++)
                {
                    string value = Binary[i, j];
                    Binary[i,j] = HexConvertedToBinary(value);
                }
            }
            return Binary; 
        }

        //Convert cipherText&cipherKey from blocks to Martix
        //Mario-->Done
        public void BlockToState(string PlainTxt, string cipherKey)
        {
            //ADD Plain text to Matrix (PlainTextMatrix)
            int k = 2;
            for(int i=0;i<4;i++)
            {
                for(int j=0;j<4;j++)
                {
                    PlainTextMatrix[j,i] = PlainTxt[k].ToString()+PlainTxt[k+1].ToString();
                    k += 2;
                }
            }
            //ADD Cipher Key to Matrix (CipherKeyMatrix)
            int l = 2;
            for(int m=0;m<4;m++)
            {
                for(int n=0;n<4;n++)
                {
                    CipherKeyMatrix[n, m] = cipherKey[l].ToString() + cipherKey[k + 1].ToString();
                    l += 2;
                }
            }
        }

        //PlainText XOR CipherKey
        //Convert PlainText and CipherKey to Binary first
        //Samar Hossam 
        //Made By Mario
        public string XOR(string a,string b)
        {
            //0001 1100
            string sum= "";
            for(int i=0; i<4;i++)
            {
                if (a[i] != b[i])
                {
                    sum += '1';
                }
                else
                    sum += '0';
            }
            return sum; 
        }

        public string[,] AddRoundKey()
        {
            string[,] MatrixForPlainBinary = ToBinary(PlainTextMatrix);
            string[,] MatrixForKeyBinary = ToBinary(CipherKeyMatrix);
            string[,] MatrixForXOR = new string[4, 4];
            for(int i=0; i<4; i++)
            {
                for(int j=0; j<4;j++)
                {
                    MatrixForXOR[i,j] = XOR(MatrixForPlainBinary[i,j],MatrixForKeyBinary[i,j]);
                }
            }
            return MatrixForXOR;
        }

        //Convert Each value with SBox
        //Take the array with comes from AddRoundKey
        //Mario
        public static readonly Dictionary<string, int> HexaNumbers = new Dictionary<string, int>
        {
            {"A",11},
            {"B",12},
            {"C",13},
            {"D",14},
            {"E",15},
            {"F",16}

        };
        public int ReturnNumberForsBox(string n)
        {
            if(n=="A"|| n == "B" || n == "C" || n == "D" || n == "E" || n == "E" || n == "F")
            {
                return HexaNumbers[n];
            }
            else
            {
               return Int32.Parse(n);
            }
        }
        public string[,] SubBytes(string[,] RoundKeyState)
        {
            for(int i=0;i<4;i++)
            {
                for(int j=0;j<4;j++)
                {
                    string s = (RoundKeyState[i, j]);
                    int n1 = ReturnNumberForsBox(s[0].ToString());
                    int n2 = ReturnNumberForsBox(s[1].ToString());
                    string L = sBox[n1, n2].ToString();
                    RoundKeyState[i,j] = sBox[n1,n2];
                }
            }
            return RoundKeyState;
        }

        //ShiftRows
        //DON'T TOUCH first row
        //Shift row 2 --> 1 Time
        //Shift row 3 --> 2 Times
        //Shift row4 --> 3 Times
        //Shifts To the left
        //Mario
        public string[,] ShiftRows(string[,] SubBytesState)
        {
            //Shift Row 2
            //Shift 1 Time
            string[] Row2 = new string[4];
            string[] Row2Extend = new string[4];
            for(int i=0;i<4;i++)
            {
                Row2[i] = SubBytesState[1, i];
            }
            for(int i=0;i<4;i++)
            {
                Row2Extend[i] = Row2[(i+1)%4];
            }
            for(int i=0;i<4;i++)
            {
                SubBytesState[1, i] = Row2Extend[i];
            }

            //Shift Row 3
            //Shift 2 Times
            string[] Row3 = new string[4];
            string[] Row3Extend = new string[4];
            for (int i = 0; i < 4; i++)
            {
                Row3[i] = SubBytesState[2, i];
            }
            for (int i = 0; i < 4; i++)
            {
                Row3Extend[i] = Row2[(i + 2) % 4];
            }
            for (int i = 0; i < 4; i++)
            {
                SubBytesState[2, i] = Row3Extend[i];
            }

            //Shift Row 4
            //Shift 3 Times
            string[] Row4 = new string[4];
            string[] Row4Extend = new string[4];
            for (int i = 0; i < 4; i++)
            {
                Row4[i] = SubBytesState[3, i];
            }
            for (int i = 0; i < 4; i++)
            {
                Row4Extend[i] = Row2[(i + 3) % 4];
            }
            for (int i = 0; i < 4; i++)
            {
                SubBytesState[3, i] = Row4Extend[i];
            }

            return SubBytesState;

        }

        //Mix Columns
        //Perry
        public string[,] MixColumns(string[,] ShiftRowsState)
        {

        }
        //Generate RoundKeys
        //Perry
        
        public override string Decrypt(string cipherText, string key)
        {
           
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }
    }
}
