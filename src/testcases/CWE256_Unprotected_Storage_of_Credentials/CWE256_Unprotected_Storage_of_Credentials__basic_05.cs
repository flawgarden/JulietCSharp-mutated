/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE256_Unprotected_Storage_of_Credentials__basic_05.cs
Label Definition File: CWE256_Unprotected_Storage_of_Credentials__basic.label.xml
Template File: sources-sinks-05.tmpl.cs
*/
/*
* @description
* CWE: 256 Unprotected Storage of Credentials
* BadSource:  Read password from a .txt file
* GoodSource: Read password from a .txt file (from the property named password) and then decrypt it
* Sinks:
*    GoodSink: Decrypt password and use decrypted password as password to connect to DB
*    BadSink : Use password as password to connect to DB
* Flow Variant: 05 Control flow: if(privateTrue) and if(privateFalse)
*
* */
using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;
using System.Security.Cryptography;
using System.IO;
using System.Text;

namespace testcases.CWE256_Unprotected_Storage_of_Credentials
{
class CWE256_Unprotected_Storage_of_Credentials__basic_05 : AbstractTestCase
{

    /* The two variables below are not defined as "readonly", but are never
     * assigned any other value, so a tool should be able to identify that
     * reads of these will always return their initialized values.
     */
    private bool privateTrue = true;
    private bool privateFalse = false;
#if (!OMITBAD)
    public override void Bad()
    {
        string password;
        if (privateTrue)
        {
            password = ""; /* init password */
            /* retrieve the password */
            try
            {
                password = Encoding.UTF8.GetString(File.ReadAllBytes("../../../common/strong_password_file.txt"));
            }
            catch (IOException exceptIO)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error with file reading", exceptIO);
            }
            /* POTENTIAL FLAW: The raw password read from the .txt file is passed on (without being decrypted) */
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure password is inititialized before the Sink to avoid compiler errors */
            password = null;
        }
        if (privateTrue)
        {
            /* POTENTIAL FLAW: Use password as a password to connect to a DB  (without being decrypted) */
            using (SqlConnection dBConnection = new SqlConnection(@"Data Source=(local);Initial Catalog=CWE256;User ID=" + "sa" + ";Password=" + password))
            {
                try
                {
                    dBConnection.Open();
                }
                catch (SqlException exceptSql)
                {
                    IO.Logger.Log(NLog.LogLevel.Warn, "Error with database connection", exceptSql);
                }
            }
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B1() - use goodsource and badsink by changing first privateTrue to privateFalse */
    private void GoodG2B1()
    {
        string password;
        if (privateFalse)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure password is inititialized before the Sink to avoid compiler errors */
            password = null;
        }
        else
        {
            password = ""; /* init password */
            /* retrieve the password */
            try
            {
                password = Encoding.UTF8.GetString(File.ReadAllBytes("../../../common/strong_password_file.txt"));
            }
            catch (IOException exceptIO)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error with file reading", exceptIO);
            }
            /* FIX: password is decrypted before being passed on */
            {
                using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
                {
                    aesAlg.Key = Encoding.UTF8.GetBytes("ABCDEFGHABCDEFGH");
                    aesAlg.IV = new byte[16];
                    // Create a decryptor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    // Create the streams used for decryption.
                    using (MemoryStream msDecrypt = new MemoryStream(File.ReadAllBytes("../../../common/strong_password_file.txt")))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                // Read the decrypted bytes from the decrypting stream
                                // and place them in a string.
                                password = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
            }
        }
        if (privateTrue)
        {
            /* POTENTIAL FLAW: Use password as a password to connect to a DB  (without being decrypted) */
            using (SqlConnection dBConnection = new SqlConnection(@"Data Source=(local);Initial Catalog=CWE256;User ID=" + "sa" + ";Password=" + password))
            {
                try
                {
                    dBConnection.Open();
                }
                catch (SqlException exceptSql)
                {
                    IO.Logger.Log(NLog.LogLevel.Warn, "Error with database connection", exceptSql);
                }
            }
        }
    }

    /* GoodG2B2() - use goodsource and badsink by reversing statements in first if */
    private void GoodG2B2()
    {
        string password;
        if (privateTrue)
        {
            password = ""; /* init password */
            /* retrieve the password */
            try
            {
                password = Encoding.UTF8.GetString(File.ReadAllBytes("../../../common/strong_password_file.txt"));
            }
            catch (IOException exceptIO)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error with file reading", exceptIO);
            }
            /* FIX: password is decrypted before being passed on */
            {
                using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
                {
                    aesAlg.Key = Encoding.UTF8.GetBytes("ABCDEFGHABCDEFGH");
                    aesAlg.IV = new byte[16];
                    // Create a decryptor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    // Create the streams used for decryption.
                    using (MemoryStream msDecrypt = new MemoryStream(File.ReadAllBytes("../../../common/strong_password_file.txt")))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                // Read the decrypted bytes from the decrypting stream
                                // and place them in a string.
                                password = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure password is inititialized before the Sink to avoid compiler errors */
            password = null;
        }
        if (privateTrue)
        {
            /* POTENTIAL FLAW: Use password as a password to connect to a DB  (without being decrypted) */
            using (SqlConnection dBConnection = new SqlConnection(@"Data Source=(local);Initial Catalog=CWE256;User ID=" + "sa" + ";Password=" + password))
            {
                try
                {
                    dBConnection.Open();
                }
                catch (SqlException exceptSql)
                {
                    IO.Logger.Log(NLog.LogLevel.Warn, "Error with database connection", exceptSql);
                }
            }
        }
    }

    /* goodB2G1() - use badsource and goodsink by changing second privateTrue to privateFalse */
    private void GoodB2G1()
    {
        string password;
        if (privateTrue)
        {
            password = ""; /* init password */
            /* retrieve the password */
            try
            {
                password = Encoding.UTF8.GetString(File.ReadAllBytes("../../../common/strong_password_file.txt"));
            }
            catch (IOException exceptIO)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error with file reading", exceptIO);
            }
            /* POTENTIAL FLAW: The raw password read from the .txt file is passed on (without being decrypted) */
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure password is inititialized before the Sink to avoid compiler errors */
            password = null;
        }
        if (privateFalse)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
            IO.WriteLine("Benign, fixed string");
        }
        else
        {
            /* FIX: password is decrypted before being used as a database password */
            {
                using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
                {
                    aesAlg.Key = Encoding.UTF8.GetBytes("ABCDEFGHABCDEFGH");
                    aesAlg.IV = new byte[16];
                    // Create a decryptor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    // Create the streams used for decryption.
                    using (MemoryStream msDecrypt = new MemoryStream(File.ReadAllBytes("../../../common/strong_password_file.txt")))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                // Read the decrypted bytes from the decrypting stream
                                // and place them in a string.
                                password = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
            }
            using (SqlConnection dBConnection = new SqlConnection(@"Data Source=(local);Initial Catalog=CWE256;User ID=sa;Password=" + password))
            {
                try
                {
                    dBConnection.Open();
                }
                catch (SqlException exceptSql)
                {
                    IO.Logger.Log(NLog.LogLevel.Warn, "Error with database connection", exceptSql);
                }
            }
        }
    }

    /* goodB2G2() - use badsource and goodsink by reversing statements in second if  */
    private void GoodB2G2()
    {
        string password;
        if (privateTrue)
        {
            password = ""; /* init password */
            /* retrieve the password */
            try
            {
                password = Encoding.UTF8.GetString(File.ReadAllBytes("../../../common/strong_password_file.txt"));
            }
            catch (IOException exceptIO)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error with file reading", exceptIO);
            }
            /* POTENTIAL FLAW: The raw password read from the .txt file is passed on (without being decrypted) */
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure password is inititialized before the Sink to avoid compiler errors */
            password = null;
        }
        if (privateTrue)
        {
            /* FIX: password is decrypted before being used as a database password */
            {
                using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
                {
                    aesAlg.Key = Encoding.UTF8.GetBytes("ABCDEFGHABCDEFGH");
                    aesAlg.IV = new byte[16];
                    // Create a decryptor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    // Create the streams used for decryption.
                    using (MemoryStream msDecrypt = new MemoryStream(File.ReadAllBytes("../../../common/strong_password_file.txt")))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                // Read the decrypted bytes from the decrypting stream
                                // and place them in a string.
                                password = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
            }
            using (SqlConnection dBConnection = new SqlConnection(@"Data Source=(local);Initial Catalog=CWE256;User ID=sa;Password=" + password))
            {
                try
                {
                    dBConnection.Open();
                }
                catch (SqlException exceptSql)
                {
                    IO.Logger.Log(NLog.LogLevel.Warn, "Error with database connection", exceptSql);
                }
            }
        }
    }

    public override void Good()
    {
        GoodG2B1();
        GoodG2B2();
        GoodB2G1();
        GoodB2G2();
    }
#endif //omitgood
}
}
