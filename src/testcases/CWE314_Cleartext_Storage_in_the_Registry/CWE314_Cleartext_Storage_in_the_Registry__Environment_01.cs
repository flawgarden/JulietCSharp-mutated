/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE314_Cleartext_Storage_in_the_Registry__Environment_01.cs
Label Definition File: CWE314_Cleartext_Storage_in_the_Registry.label.xml
Template File: sources-sinks-01.tmpl.cs
*/
/*
* @description
* CWE: 314 Cleartext storage in the registry
* BadSource: Environment Read data from an environment variable
* GoodSource: A hardcoded string
* Sinks:
*    GoodSink: Hash data before storing in registry
*    BadSink : Store data directly in registry
* Flow Variant: 01 Baseline
*
* */

using TestCaseSupport;
using System;

using Microsoft.Win32;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace testcases.CWE314_Cleartext_Storage_in_the_Registry
{
class CWE314_Cleartext_Storage_in_the_Registry__Environment_01 : AbstractTestCase
{
#if (!OMITBAD)
    public override void Bad()
    {
        string data;
        /* get environment variable ADD */
        /* POTENTIAL FLAW: Read data from an environment variable */
        data = Environment.GetEnvironmentVariable("ADD");
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
    public override void Good()
    {
        GoodG2B();
        GoodB2G();
    }

    /* goodG2B() - use goodsource and badsink */
    private void GoodG2B()
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
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
    private void GoodB2G()
    {
        string data;
        /* get environment variable ADD */
        /* POTENTIAL FLAW: Read data from an environment variable */
        data = Environment.GetEnvironmentVariable("ADD");
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
#endif //omitgood
}
}
