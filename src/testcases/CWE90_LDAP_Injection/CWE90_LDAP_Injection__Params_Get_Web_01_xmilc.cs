//Original file region: 29, 48, null, null
//Mutated file region: 49, 70, null, null
//CodeQL original results: [90]
//Snyk original results: [90]
//Semgrep original results: []
//Insider original results: []
//-------------
//Semgrep analysis results: []
//CodeQL analysis results: [835, 563]
//Snyk analysis results: [90]
//Insider analysis results: []
//Original file name: src/testcases/CWE90_LDAP_Injection/CWE90_LDAP_Injection__Params_Get_Web_01.cs
//Original file CWE's: [90]  
//Original file kind: fail
//Program:
// Mutation info: Insert template from sensitivity/field/constructorChains with name constructor_chains_neutral
// Used extensions: ~[EXPR_bool@1002]~ -> ~[EXPR_string@1]~ != null && ~[EXPR_string@1]~.Contains(~[EXPR_string@1001]~)
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using HelperFields;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE90_LDAP_Injection__Params_Get_Web_01980547.cs
Label Definition File: CWE90_LDAP_Injection.label.xml
Template File: sources-sink-01.tmpl.cs
*/
/*
* @description
* CWE: 90 LDAP Injection
* BadSource: Params_Get_Web Read data from a querystring using Params.Get()
* GoodSource: A hardcoded string
* BadSink:  data concatenated into LDAP search, which could result in LDAP Injection
* Flow Variant: 01 Baseline
*
* */

using TestCaseSupport;
using System;

using System.DirectoryServices;

using System.Web;


namespace testcases.CWE90_LDAP_Injection
{

class MutatedCWE90_LDAP_Injection__Params_Get_Web_01980547 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    /* uses badsource and badsink */
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* POTENTIAL FLAW: Read data from a querystring using Params.Get */
        data = req.Params.Get("name");
        using (DirectoryEntry de = new DirectoryEntry())
        {
            /* POTENTIAL FLAW: data concatenated into LDAP search, which could result in LDAP Injection */
ConstructorChains cc = new ConstructorChains(false, data);
data = cc.getText("JvpWTBLbzOelMBtQLOKhOLyGnWPRtzsWHfK0g5CUZPUHNKScnOx5FGX87is6v4s9g" != null && "JvpWTBLbzOelMBtQLOKhOLyGnWPRtzsWHfK0g5CUZPUHNKScnOx5FGX87is6v4s9g".Contains("13uPLzI"));
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
    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B(req, resp);
    }

    /* goodG2B() - uses goodsource and badsink */
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
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
#endif //omitgood
}
}
