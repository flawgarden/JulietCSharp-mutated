/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE314_Cleartext_Storage_in_the_Registry__Database_42.cs
Label Definition File: CWE314_Cleartext_Storage_in_the_Registry.label.xml
Template File: sources-sinks-42.tmpl.cs
*/
/*
 * @description
 * CWE: 314 Cleartext storage in the registry
 * BadSource: Database Read data from a database
 * GoodSource: A hardcoded string
 * Sinks:
 *    GoodSink: Hash data before storing in registry
 *    BadSink : Store data directly in registry
 * Flow Variant: 42 Data flow: data returned from one method to another in the same class
 *
 * */

using TestCaseSupport;
using System;

using Microsoft.Win32;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Web;

using Microsoft.Data.SqlClient;

namespace testcases.CWE314_Cleartext_Storage_in_the_Registry
{
class CWE314_Cleartext_Storage_in_the_Registry__Database_42 : AbstractTestCase
{
#if (!OMITBAD)
    private static string BadSource()
    {
        string data;
        data = ""; /* Initialize data */
        /* Read data from a database */
        {
            try
            {
                /* setup the connection */
                using (SqlConnection connection = IO.GetDBConnection())
                {
                    connection.Open();
                    /* prepare and execute a (hardcoded) query */
                    using (SqlCommand command = new SqlCommand(null, connection))
                    {
                        command.CommandText = "select name from users where id=0";
                        command.Prepare();
                        using (SqlDataReader dr = command.ExecuteReader())
                        {
                            /* POTENTIAL FLAW: Read data from a database query SqlDataReader */
                            data = dr.GetString(1);
                        }
                    }
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error with SQL statement");
            }
        }
        return data;
    }

    public override void Bad()
    {
        string data = BadSource();
        using (SecureString secureData = new SecureString())
        {
            for (int i = 0; i < data.Length; i++)
            {
                secureData.AppendChar(data[i]);
            }
            /* POTENTIAL FLAW: Store data directly in registry */
            RegistryKey key = Registry.CurrentUser.OpenSubKey("Software", true);
            key.CreateSubKey("CWEparent");
            key = key.OpenSubKey("CWEparent", true);
            key.CreateSubKey("TestingCWE");
            key = key.OpenSubKey("TestingCWE", true);
            key.SetValue("CWE", secureData);
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    private static string GoodG2BSource()
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
        return data;
    }

    private static void GoodG2B()
    {
        string data = GoodG2BSource();
        using (SecureString secureData = new SecureString())
        {
            for (int i = 0; i < data.Length; i++)
            {
                secureData.AppendChar(data[i]);
            }
            /* POTENTIAL FLAW: Store data directly in registry */
            RegistryKey key = Registry.CurrentUser.OpenSubKey("Software", true);
            key.CreateSubKey("CWEparent");
            key = key.OpenSubKey("CWEparent", true);
            key.CreateSubKey("TestingCWE");
            key = key.OpenSubKey("TestingCWE", true);
            key.SetValue("CWE", secureData);
        }
    }

    /* goodB2G() - use badsource and goodsink */
    private static string GoodB2GSource()
    {
        string data;
        data = ""; /* Initialize data */
        /* Read data from a database */
        {
            try
            {
                /* setup the connection */
                using (SqlConnection connection = IO.GetDBConnection())
                {
                    connection.Open();
                    /* prepare and execute a (hardcoded) query */
                    using (SqlCommand command = new SqlCommand(null, connection))
                    {
                        command.CommandText = "select name from users where id=0";
                        command.Prepare();
                        using (SqlDataReader dr = command.ExecuteReader())
                        {
                            /* POTENTIAL FLAW: Read data from a database query SqlDataReader */
                            data = dr.GetString(1);
                        }
                    }
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error with SQL statement");
            }
        }
        return data;
    }

    private static void GoodB2G()
    {
        string data = GoodB2GSource();
        /* FIX: Hash data before storing in registry */
        {
            string salt = "ThisIsMySalt";
            using (SHA512CryptoServiceProvider sha512 = new SHA512CryptoServiceProvider())
            {
                byte[] buffer = Encoding.UTF8.GetBytes(string.Concat(salt, data));
                byte[] hashedCredsAsBytes = sha512.ComputeHash(buffer);
                data = IO.ToHex(hashedCredsAsBytes);
            }
        }
        using (SecureString secureData = new SecureString())
        {
            for (int i = 0; i < data.Length; i++)
            {
                secureData.AppendChar(data[i]);
            }
            RegistryKey key = Registry.CurrentUser.OpenSubKey("Software", true);
            key.CreateSubKey("CWEparent");
            key = key.OpenSubKey("CWEparent", true);
            key.CreateSubKey("TestingCWE");
            key = key.OpenSubKey("TestingCWE", true);
            key.SetValue("CWE", secureData);
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
