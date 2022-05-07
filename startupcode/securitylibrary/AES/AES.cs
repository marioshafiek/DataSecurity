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
                       //0    1      2     3    4     5     6      7     8    9      10   11    12    13     14    15     
        int[,] sBox = {{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
                      { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
                      { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
                      { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
                      {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
                      { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
                      { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
                      { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
                      { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
                      { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
                      { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
                      { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
                      { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
                      { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
                      { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
                      { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }};
        

        //Matrices For CipherText and Key
        string[,] PlainTextMatrix = new string[4,4];
        string[,] CipherKeyMatrix = new string[4, 4];

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
                    RoundKeyState[i,j] = sBox[n1,n2].ToString();
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
