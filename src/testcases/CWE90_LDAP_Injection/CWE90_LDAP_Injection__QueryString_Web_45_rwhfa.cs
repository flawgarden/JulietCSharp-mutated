using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE90_LDAP_Injection__QueryString_Web_45594073.cs
Label Definition File: CWE90_LDAP_Injection.label.xml
Template File: sources-sink-45.tmpl.cs
*/
/*
 * @description
 * CWE: 90 LDAP Injection
 * BadSource: QueryString_Web Parse id param out of the URL query string (without using getParameter())
 * GoodSource: A hardcoded string
 * Sinks:
 *    BadSink : data concatenated into LDAP search, which could result in LDAP Injection
 * Flow Variant: 45 Data flow: data passed as a private class member variable from one function to another in the same class
 *
 * */

using TestCaseSupport;
using System;

using System.DirectoryServices;

using System.Web;


namespace testcases.CWE90_LDAP_Injection
{

class MutatedCWE90_LDAP_Injection__QueryString_Web_45594073 : AbstractTestCaseWeb
{

    private string dataBad;
    private string dataGoodG2B;
#if (!OMITBAD)
    private void BadSink(HttpRequest req, HttpResponse resp)
    {
        string data = dataBad;
        using (DirectoryEntry de = new DirectoryEntry())
        {
            /* POTENTIAL FLAW: data concatenated into LDAP search, which could result in LDAP Injection */
            using (DirectorySearcher search = new DirectorySearcher(de))
            {
                search.Filter = "(&(objectClass=user)(employeename=" + data + "))";
                search.PropertiesToLoad.Add("mail");
                search.PropertiesToLoad.Add("telephonenumber");
                SearchResult sresult = search.FindOne();
            }
        }
    }

    /* uses badsource and badsink */
public string paramOrEmpty(int value, string param) {
    if (param.Length == value) {
        return param;
    } else if (value > param.Length) {
        paramOrEmpty(--value, param);
    } else {
        return "";
    }
    return "";
}public string paramOrEmptyMutual1(int value, string param) {
    if (param.Length == value) {
        return param;
    } else if (value > param.Length) {
        paramOrEmptyMutual2(value, param);
    } else {
        return "";
    }
    return "";
}public string paramOrEmptyMutual2(int value, string param) {
    return paramOrEmptyMutual1(--value, param);
}
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        data = ""; /* initialize data in case id is not in query string */
        /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
        {
            if (req.QueryString["id"] != null)
            {
                data = req.QueryString["id"];
            }
        }
        dataBad = data;
dataBad = paramOrEmptyMutual1(dataBad.Length, dataBad);
        BadSink(req, resp);
    }
#endif //omitbad
#if (!OMITGOOD)
    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B(req, resp);
    }

    private void GoodG2BSink(HttpRequest req, HttpResponse resp)
    {
        string data = dataGoodG2B;
        using (DirectoryEntry de = new DirectoryEntry())
        {
            /* POTENTIAL FLAW: data concatenated into LDAP search, which could result in LDAP Injection */
            using (DirectorySearcher search = new DirectorySearcher(de))
            {
                search.Filter = "(&(objectClass=user)(employeename=" + data + "))";
                search.PropertiesToLoad.Add("mail");
                search.PropertiesToLoad.Add("telephonenumber");
                SearchResult sresult = search.FindOne();
            }
        }
    }

    /* goodG2B() - use goodsource and badsink */
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
        dataGoodG2B = data;
        GoodG2BSink(req, resp);
    }
#endif //omitgood
}
}
