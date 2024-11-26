// Mutation info: Insert template from sensitivity/collections/linq with name linq_simple_orderby_thenby_positive
// Used extensions: ~[MACRO_CollectionName@1001]~ -> collection42 | ~[MACRO_CollectionName@1002]~ -> collection42 | ~[MACRO_Create_Collection@1003]~ -> ICollection<string> ~[MACRO_CollectionName@1001]~ = new List<string>(); | ~[MACRO_FixedVar@1004]~ -> ~[VAR_string@1]~ | ~[MACRO_FixedVar@1005]~ -> ~[VAR_string@1]~ | ~[MACRO_From@1006]~ -> from ~[MACRO_Item@1002]~ in ~[MACRO_CollectionName@1001]~ | ~[MACRO_Item@1002]~ -> item42 | ~[MACRO_GetItem@1007]~ -> query42.First() | ~[MACRO_Item@1008]~ -> item42 | ~[MACRO_Item@1009]~ -> item42 | ~[MACRO_QueryName@1010]~ -> query42 | ~[MACRO_SimpleSelect@1011]~ -> select ~[MACRO_Item@1001]~ | ~[MACRO_Item@1001]~ -> item42 | ~[MACRO_CollectionName@1001]~ -> collection42 | ~[MACRO_CollectionName@1002]~ -> collection42 | ~[MACRO_Create_Collection@1003]~ -> ICollection<string> ~[MACRO_CollectionName@1001]~ = new List<string>(); | ~[MACRO_FixedVar@1004]~ -> ~[VAR_string@1]~ | ~[MACRO_FixedVar@1005]~ -> ~[VAR_string@1]~ | ~[MACRO_From@1006]~ -> from ~[MACRO_Item@1002]~ in ~[MACRO_CollectionName@1001]~ | ~[MACRO_Item@1002]~ -> item42 | ~[MACRO_GetItem@1007]~ -> query42.First() | ~[MACRO_Item@1008]~ -> item42 | ~[MACRO_Item@1009]~ -> item42 | ~[MACRO_QueryName@1010]~ -> query42 | ~[MACRO_SimpleSelect@1011]~ -> select ~[MACRO_Item@1001]~ | ~[MACRO_Item@1001]~ -> item42
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE601_Open_Redirect__Web_QueryString_Web_07703946.cs
Label Definition File: CWE601_Open_Redirect__Web.label.xml
Template File: sources-sink-07.tmpl.cs
*/
/*
* @description
* CWE: 601 Open Redirect
* BadSource: QueryString_Web Parse id param out of the URL query string (without using getParameter())
* GoodSource: A hardcoded string
* BadSink:  place redirect string directly into redirect api call
* Flow Variant: 07 Control flow: if(privateFive==5) and if(privateFive!=5)
*
* */

using TestCaseSupport;
using System;

using System.Web;


namespace testcases.CWE601_Open_Redirect
{

class MutatedCWE601_Open_Redirect__Web_QueryString_Web_07703946 : AbstractTestCaseWeb
{

    /* The variable below is not declared "readonly", but is never assigned
     * any other value so a tool should be able to identify that reads of
     * this will always give its initialized value.
     */
    private int privateFive = 5;
#if (!OMITBAD)
    /* uses badsource and badsink */
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (privateFive == 5)
        {
            data = ""; /* initialize data in case id is not in query string */
            /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
            {
                if (req.QueryString["id"] != null)
                {
                    data = req.QueryString["id"];
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }
        if (data != null)
        {
            /* This prevents \r\n (and other chars) and should prevent incidentals such
             * as HTTP Response Splitting and HTTP Header Injection.
             */
            Uri uri;
            try
            {
                uri = new Uri(data);
            }
            catch (UriFormatException exceptURISyntax)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptURISyntax, "Invalid redirect URL");
ICollection<string> collection42 = new List<string>();
collection42.Add("a");
collection42.Add("a" + data);
var query42 =
    from item42 in collection42
    orderby item42[0], item42.Length descending
    select item42;
data = query42.First();
                resp.Write("Invalid redirect URL");
                return;
            }
            /* POTENTIAL FLAW: redirect is sent verbatim; escape the string to prevent ancillary issues like XSS, Response splitting etc */
            resp.Redirect(data);
            return;
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B1() - use goodsource and badsink by changing privateFive==5 to privateFive!=5 */
    private void GoodG2B1(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (privateFive != 5)
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
        if (data != null)
        {
            /* This prevents \r\n (and other chars) and should prevent incidentals such
             * as HTTP Response Splitting and HTTP Header Injection.
             */
            Uri uri;
            try
            {
                uri = new Uri(data);
            }
            catch (UriFormatException exceptURISyntax)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptURISyntax, "Invalid redirect URL");
                resp.Write("Invalid redirect URL");
                return;
            }
            /* POTENTIAL FLAW: redirect is sent verbatim; escape the string to prevent ancillary issues like XSS, Response splitting etc */
            resp.Redirect(data);
            return;
        }
    }

    /* GoodG2B2() - use goodsource and badsink by reversing statements in if */
    private void GoodG2B2(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (privateFive == 5)
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
        if (data != null)
        {
            /* This prevents \r\n (and other chars) and should prevent incidentals such
             * as HTTP Response Splitting and HTTP Header Injection.
             */
            Uri uri;
            try
            {
                uri = new Uri(data);
            }
            catch (UriFormatException exceptURISyntax)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptURISyntax, "Invalid redirect URL");
                resp.Write("Invalid redirect URL");
                return;
            }
            /* POTENTIAL FLAW: redirect is sent verbatim; escape the string to prevent ancillary issues like XSS, Response splitting etc */
            resp.Redirect(data);
            return;
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
