//Original file region: 29, 60, null, null
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
//Original file name: src/testcases/CWE90_LDAP_Injection/CWE90_LDAP_Injection__QueryString_Web_42.cs
//Original file CWE's: [90]  
//Original file kind: fail
//Mutation info: Insert template from sensitivity/operators/operators with name explicit_binary_operator_minus_call_negative 
//Used extensions: 
//Program:
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using HelperOperators;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE90_LDAP_Injection__QueryString_Web_42403438.cs
Label Definition File: CWE90_LDAP_Injection.label.xml
Template File: sources-sink-42.tmpl.cs
*/
/*
 * @description
 * CWE: 90 LDAP Injection
 * BadSource: QueryString_Web Parse id param out of the URL query string (without using getParameter())
 * GoodSource: A hardcoded string
 * BadSink:  data concatenated into LDAP search, which could result in LDAP Injection
 * Flow Variant: 42 Data flow: data returned from one method to another in the same class
 *
 * */

using TestCaseSupport;
using System;

using System.DirectoryServices;

using System.Web;


namespace testcases.CWE90_LDAP_Injection
{

class MutatedCWE90_LDAP_Injection__QueryString_Web_42403438 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    private static string BadSource(HttpRequest req, HttpResponse resp)
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
        return data;
    }

    /* use badsource and badsink */
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data = BadSource(req, resp);
        using (DirectoryEntry de = new DirectoryEntry())
        {
            /* POTENTIAL FLAW: data concatenated into LDAP search, which could result in LDAP Injection */

var operators1943 = new SpecialOperatorsStringHolder(data);
var srotarepo3491 = new SpecialOperatorsStringHolder("1zzjat1YdEYVnpjH1uUAWKcO1jF3tWZgAdFm5IgtRirsfQkYVVsuMverXls1n7pHp1VJj6MsOktydtsl9riXop");
var sum41324 = operators1943 - srotarepo3491;
data = sum41324.ToString();
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
    private static string GoodG2BSource(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
        return data;
    }

    /* goodG2B() - use goodsource and badsink */
    private static void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data = GoodG2BSource(req, resp);
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
        GoodG2B(req, resp);
    }
#endif //omitgood
}
}
