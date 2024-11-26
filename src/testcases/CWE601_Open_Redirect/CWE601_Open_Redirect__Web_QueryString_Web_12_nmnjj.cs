//Original file region: 27, 69, null, null
//Mutated file region: 47, 97, null, null
//CodeQL original results: [601]
//Snyk original results: [601]
//Semgrep original results: []
//Insider original results: []
//-------------
//Semgrep analysis results: []
//CodeQL analysis results: [563]
//Snyk analysis results: [601]
//Insider analysis results: []
//Original file name: src/testcases/CWE601_Open_Redirect/CWE601_Open_Redirect__Web_QueryString_Web_12.cs
//Original file CWE's: [601]  
//Original file kind: fail
//Program:
// Mutation info: Insert template from sensitivity/exceptions/tryCatchFinally with name try_cath_finally_negative
// Used extensions: 
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using HelperExceptions;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE601_Open_Redirect__Web_QueryString_Web_12706556.cs
Label Definition File: CWE601_Open_Redirect__Web.label.xml
Template File: sources-sink-12.tmpl.cs
*/
/*
* @description
* CWE: 601 Open Redirect
* BadSource: QueryString_Web Parse id param out of the URL query string (without using getParameter())
* GoodSource: A hardcoded string
* BadSink:  place redirect string directly into redirect api call
* Flow Variant: 12 Control flow: if(IO.StaticReturnsTrueOrFalse())
*
* */

using TestCaseSupport;
using System;

using System.Web;


namespace testcases.CWE601_Open_Redirect
{

class MutatedCWE601_Open_Redirect__Web_QueryString_Web_12706556 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    /* uses badsource and badsink - see how tools report flaws that don't always occur */
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (IO.StaticReturnsTrueOrFalse())
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
string tmpUnique42 = data;
try {
  throw new Exception1(data);
} catch (Exception1 e) {
    data = tmpUnique42;
} finally {
    data = "";
}
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
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink by changing the "if" so that
     * both branches use the GoodSource */
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (IO.StaticReturnsTrueOrFalse())
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
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

    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B(req, resp);
    }
#endif //omitgood
}
}
