using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE90_LDAP_Injection__QueryString_Web_15977347.cs
Label Definition File: CWE90_LDAP_Injection.label.xml
Template File: sources-sink-15.tmpl.cs
*/
/*
* @description
* CWE: 90 LDAP Injection
* BadSource: QueryString_Web Parse id param out of the URL query string (without using getParameter())
* GoodSource: A hardcoded string
* BadSink:  data concatenated into LDAP search, which could result in LDAP Injection
* Flow Variant: 15 Control flow: switch(6)
*
* */

using TestCaseSupport;
using System;

using System.DirectoryServices;

using System.Web;


namespace testcases.CWE90_LDAP_Injection
{

class MutatedCWE90_LDAP_Injection__QueryString_Web_15977347 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    /* uses badsource and badsink */
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data = null;
        switch (6)
        {
        case 6:
            data = ""; /* initialize data in case id is not in query string */
            /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
            {
                if (req.QueryString["id"] != null)
                {
                    data = req.QueryString["id"];
                }
            }
            break;
        default:
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
            break;
        }
        using (DirectoryEntry de = new DirectoryEntry())
        {
            /* POTENTIAL FLAW: data concatenated into LDAP search, which could result in LDAP Injection */

var anon42342 = (data, "RIR4llRGTUJZvZfB0RqTFLry7s6mR2JWqgflN");
(string Lupa, string Pupa) difNaming412 = anon42342;
data = difNaming412.Pupa;
            using (DirectorySearcher search = new DirectorySearcher(de))
            {
                search.Filter = "(&(objectClass=user)(employeename=" + data + "))";
                search.PropertiesToLoad.Add("mail");
                search.PropertiesToLoad.Add("telephonenumber");
                SearchResult sresult = search.FindOne();
            }
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B1() - use goodsource and badsink by changing the  switch to switch(5) */
    private void GoodG2B1(HttpRequest req, HttpResponse resp)
    {
        string data = null;
        switch (5)
        {
        case 6:
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
            break;
        default:
            /* FIX: Use a hardcoded string */
            data = "foo";
            break;
        }
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

    /* GoodG2B2() - use goodsource and badsink by reversing the blocks in the switch  */
    private void GoodG2B2(HttpRequest req, HttpResponse resp)
    {
        string data = null;
        switch (6)
        {
        case 6:
            /* FIX: Use a hardcoded string */
            data = "foo";
            break;
        default:
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
            break;
        }
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

    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B1(req, resp);
        GoodG2B2(req, resp);
    }
#endif //omitgood
}
}
