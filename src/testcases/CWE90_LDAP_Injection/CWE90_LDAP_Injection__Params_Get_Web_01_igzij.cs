using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE90_LDAP_Injection__Params_Get_Web_01281995.cs
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

class MutatedCWE90_LDAP_Injection__Params_Get_Web_01281995 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    /* uses badsource and badsink */
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* POTENTIAL FLAW: Read data from a querystring using Params.Get */
        data = req.Params.Get("name");
ICollection<string> collection42 = new List<string>();
collection42.Add("a");
collection42.Add("a" + data);
var query42 =
    from item42 in collection42
    orderby item42[0], item42.Length descending
    select item42;
data = query42.First();
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
