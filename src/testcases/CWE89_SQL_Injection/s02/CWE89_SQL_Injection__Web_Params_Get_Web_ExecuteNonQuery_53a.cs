/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE89_SQL_Injection__Web_Params_Get_Web_ExecuteNonQuery_53a.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-53a.tmpl.cs
*/
/*
 * @description
 * CWE: 89 SQL Injection
 * BadSource: Params_Get_Web Read data from a querystring using Params.Get()
 * GoodSource: A hardcoded string
 * Sinks: ExecuteNonQuery
 *    GoodSink: Use prepared statement and ExecuteNonQuery (properly)
 *    BadSink : data concatenated into SQL statement used in ExecuteNonQuery(), which could result in SQL Injection
 * Flow Variant: 53 Data flow: data passed as an argument from one method through two others to a fourth; all four functions are in different classes in the same package
 *
 * */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;
using System.Data;
using System.Web;


namespace testcases.CWE89_SQL_Injection
{
class CWE89_SQL_Injection__Web_Params_Get_Web_ExecuteNonQuery_53a : AbstractTestCaseWeb
{
#if (!OMITBAD)
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* POTENTIAL FLAW: Read data from a querystring using Params.Get */
        data = req.Params.Get("name");
        CWE89_SQL_Injection__Web_Params_Get_Web_ExecuteNonQuery_53b.BadSink(data , req, resp);
    }
#endif //omitbad
#if (!OMITGOOD)
    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B(req, resp);
        GoodB2G(req, resp);
    }

    /* goodG2B() - use goodsource and badsink */
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
        CWE89_SQL_Injection__Web_Params_Get_Web_ExecuteNonQuery_53b.GoodG2BSink(data , req, resp);
    }

    /* goodB2G() - use badsource and goodsink */
    private void GoodB2G(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* POTENTIAL FLAW: Read data from a querystring using Params.Get */
        data = req.Params.Get("name");
        CWE89_SQL_Injection__Web_Params_Get_Web_ExecuteNonQuery_53b.GoodB2GSink(data , req, resp);
    }
#endif //omitgood
}
}
