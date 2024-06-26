/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE89_SQL_Injection__Web_Get_Cookies_Web_ExecuteNonQuery_54b.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-54b.tmpl.cs
*/
/*
 * @description
 * CWE: 89 SQL Injection
 * BadSource: Get_Cookies_Web Read data from the first cookie using Cookies
 * GoodSource: A hardcoded string
 * Sinks: ExecuteNonQuery
 *    GoodSink: Use prepared statement and ExecuteNonQuery (properly)
 *    BadSink : data concatenated into SQL statement used in ExecuteNonQuery(), which could result in SQL Injection
 * Flow Variant: 54 Data flow: data passed as an argument from one method through three others to a fifth; all five functions are in different classes in the same package
 *
 * */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;
using System.Data;
using System.Web;

namespace testcases.CWE89_SQL_Injection
{
class CWE89_SQL_Injection__Web_Get_Cookies_Web_ExecuteNonQuery_54b
{
#if (!OMITBAD)
    public static void BadSink(string data , HttpRequest req, HttpResponse resp)
    {
        CWE89_SQL_Injection__Web_Get_Cookies_Web_ExecuteNonQuery_54c.BadSink(data , req, resp);
    }
#endif

#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    public static void GoodG2BSink(string data , HttpRequest req, HttpResponse resp)
    {
        CWE89_SQL_Injection__Web_Get_Cookies_Web_ExecuteNonQuery_54c.GoodG2BSink(data , req, resp);
    }

    /* goodB2G() - use badsource and goodsink */
    public static void GoodB2GSink(string data , HttpRequest req, HttpResponse resp)
    {
        CWE89_SQL_Injection__Web_Get_Cookies_Web_ExecuteNonQuery_54c.GoodB2GSink(data , req, resp);
    }
#endif
}
}
