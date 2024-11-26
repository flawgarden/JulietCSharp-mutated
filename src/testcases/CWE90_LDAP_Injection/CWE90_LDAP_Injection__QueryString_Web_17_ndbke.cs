//Original file region: 29, 57, null, null
//Mutated file region: 49, 85, null, null
//CodeQL original results: [90]
//Snyk original results: [90]
//Semgrep original results: []
//Insider original results: []
//-------------
//Semgrep analysis results: []
//CodeQL analysis results: [563]
//Snyk analysis results: [90]
//Insider analysis results: []
//Original file name: src/testcases/CWE90_LDAP_Injection/CWE90_LDAP_Injection__QueryString_Web_17.cs
//Original file CWE's: [90]  
//Original file kind: fail
//Program:
// Mutation info: Insert template from sensitivity/exceptions/tryCatchFinally with name try_cath_finally_negative
// Used extensions: ~[EXPR_string@1001]~ -> String.Concat(~[EXPR_string@1001]~, ~[EXPR_string@1002]~, ~[EXPR_string@1003]~)
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using HelperExceptions;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE90_LDAP_Injection__QueryString_Web_17983916.cs
Label Definition File: CWE90_LDAP_Injection.label.xml
Template File: sources-sink-17.tmpl.cs
*/
/*
* @description
* CWE: 90 LDAP Injection
* BadSource: QueryString_Web Parse id param out of the URL query string (without using getParameter())
* GoodSource: A hardcoded string
* BadSink:  data concatenated into LDAP search, which could result in LDAP Injection
* Flow Variant: 17 Control flow: for loops
*
* */

using TestCaseSupport;
using System;

using System.DirectoryServices;

using System.Web;


namespace testcases.CWE90_LDAP_Injection
{

class MutatedCWE90_LDAP_Injection__QueryString_Web_17983916 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    /* uses badsource and badsink */
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
        for (int i = 0; i < 1; i++)
        {
            using (DirectoryEntry de = new DirectoryEntry())
            {
                /* POTENTIAL FLAW: data concatenated into LDAP search, which could result in LDAP Injection */
                using (DirectorySearcher search = new DirectorySearcher(de))
                {
string tmpUnique42 = data;
try {
  throw new Exception1(String.Concat(data, "fn2DF9q", data));
} catch (Exception1 e) {
    data = tmpUnique42;
} finally {
    data = "";
}
                    search.Filter = "(&(objectClass=user)(employeename=" + data + "))";
                    search.PropertiesToLoad.Add("mail");
                    search.PropertiesToLoad.Add("telephonenumber");
                    SearchResult sresult = search.FindOne();
                }
            }
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink by reversing the block outside the
     * for statement with the one in the for statement */
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
        for (int i = 0; i < 1; i++)
        {
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
    }

    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B(req, resp);
    }
#endif //omitgood
}
}
