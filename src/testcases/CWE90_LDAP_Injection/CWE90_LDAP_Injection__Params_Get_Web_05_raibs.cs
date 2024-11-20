//Original file region: 36, 64, null, null
//Mutated file region: 56, 96, null, null
//CodeQL original results: [90]
//Snyk original results: [90]
//Semgrep original results: []
//Insider original results: []
//-------------
//Semgrep analysis results: []
//CodeQL analysis results: [90, 563]
//Snyk analysis results: []
//Insider analysis results: []
//Original file name: src/testcases/CWE90_LDAP_Injection/CWE90_LDAP_Injection__Params_Get_Web_05.cs
//Original file CWE's: [90]  
//Original file kind: fail
//Program:
// Mutation info: Insert template from sensitivity/varargs/varargs with name varargs_combine_strings_negative
// Used extensions: ~[EXPR_string@1001]~ -> String.Concat(~[EXPR_string@1001]~, ~[EXPR_string@1002]~) | ~[EXPR_string@1002]~ -> String.Concat(~[EXPR_string@1001]~, ~[EXPR_string@1002]~)
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Generic;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE90_LDAP_Injection__Params_Get_Web_05717441.cs
Label Definition File: CWE90_LDAP_Injection.label.xml
Template File: sources-sink-05.tmpl.cs
*/
/*
* @description
* CWE: 90 LDAP Injection
* BadSource: Params_Get_Web Read data from a querystring using Params.Get()
* GoodSource: A hardcoded string
* BadSink:  data concatenated into LDAP search, which could result in LDAP Injection
* Flow Variant: 05 Control flow: if(privateTrue) and if(privateFalse)
*
* */

using TestCaseSupport;
using System;

using System.DirectoryServices;

using System.Web;


namespace testcases.CWE90_LDAP_Injection
{

class MutatedCWE90_LDAP_Injection__Params_Get_Web_05717441 : AbstractTestCaseWeb
{

    /* The two variables below are not defined as "readonly", but are never
     * assigned any other value, so a tool should be able to identify that
     * reads of these will always return their initialized values.
     */
    private bool privateTrue = true;
    private bool privateFalse = false;
#if (!OMITBAD)
    /* uses badsource and badsink */
public string getFirstString(params string[] lines) {
    return getStringWithIndex(0, lines);
}public string getStringWithIndex(int ind, params string[] lines) {
    return lines[ind];
}public String getFirstStringFromArray(params string[] lines) {
    return lines.ToList().ElementAt(0);
}public T varargsWithGenerics<T>(params T[] elements) {
    return elements[0];
}public string combineStrings(params string[] strings) {
    return String.Join(", ", strings);
}
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (privateTrue)
        {
            /* POTENTIAL FLAW: Read data from a querystring using Params.Get */
            data = req.Params.Get("name");
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }
        using (DirectoryEntry de = new DirectoryEntry())
        {
            /* POTENTIAL FLAW: data concatenated into LDAP search, which could result in LDAP Injection */
data = combineStrings(String.Concat("ueLVgNF0j1a68L5qjQGrK3sXxmQQisyaO4UXRm3ZpjpLmh6", String.Concat("GGP0", "36yR0D9rD1iZ6XrCkNhuQqWjQZXUIoelcEAc0SzHnz3CI3WEYEonODRNkOA")), data);
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
    /* goodG2B1() - use goodsource and badsink by changing privateTrue to privateFalse */
    private void GoodG2B1(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (privateFalse)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }
        else
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
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

    /* GoodG2B2() - use goodsource and badsink by reversing statements in if */
    private void GoodG2B2(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (privateTrue)
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
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
