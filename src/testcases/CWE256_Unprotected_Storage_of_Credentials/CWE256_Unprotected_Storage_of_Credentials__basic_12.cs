/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE256_Unprotected_Storage_of_Credentials__basic_12.cs
Label Definition File: CWE256_Unprotected_Storage_of_Credentials__basic.label.xml
Template File: sources-sinks-12.tmpl.cs
*/
/*
* @description
* CWE: 256 Unprotected Storage of Credentials
* BadSource:  Read password from a .txt file
* GoodSource: Read password from a .txt file (from the property named password) and then decrypt it
* Sinks:
*    GoodSink: Decrypt password and use decrypted password as password to connect to DB
*    BadSink : Use password as password to connect to DB
* Flow Variant: 12 Control flow: if(IO.StaticReturnsTrueOrFalse())
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
class CWE256_Unprotected_Storage_of_Credentials__basic_12 : AbstractTestCase
{
#if (!OMITBAD)
    public override void Bad()
    {
        string password;
        if(IO.StaticReturnsTrueOrFalse())
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
        if(IO.StaticReturnsTrueOrFalse())
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
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink by changing the first "if" so that
     * both branches use the GoodSource */
    private void GoodG2B()
    {
        string password;
        if(IO.StaticReturnsTrueOrFalse())
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
        if(IO.StaticReturnsTrueOrFalse())
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
        else
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

    /* goodB2G() - use badsource and goodsink by changing the second "if" so that
     * both branches use the GoodSink */
    private void GoodB2G()
    {
        string password;
        if(IO.StaticReturnsTrueOrFalse())
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
        if(IO.StaticReturnsTrueOrFalse())
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

    public override void Good()

    {
        GoodG2B();
        GoodB2G();
    }
#endif //omitgood
}
}
