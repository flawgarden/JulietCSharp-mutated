//Original file region: 27, 64, null, null
//Mutated file region: 46, 85, null, null
//CodeQL original results: [601]
//Snyk original results: [601]
//Semgrep original results: []
//Insider original results: []
//-------------
//Semgrep analysis results: []
//CodeQL analysis results: [835, 563]
//Snyk analysis results: [601]
//Insider analysis results: []
//Original file name: src/testcases/CWE601_Open_Redirect/CWE601_Open_Redirect__Web_Params_Get_Web_02.cs
//Original file CWE's: [601]  
//Original file kind: fail
//Mutation info: Insert template from sensitivity/nullable with name coalescing_operator_negative 
//Used extensions: 
//Program:
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE601_Open_Redirect__Web_Params_Get_Web_02405390.cs
Label Definition File: CWE601_Open_Redirect__Web.label.xml
Template File: sources-sink-02.tmpl.cs
*/
/*
* @description
* CWE: 601 Open Redirect
* BadSource: Params_Get_Web Read data from a querystring using Params.Get()
* GoodSource: A hardcoded string
* BadSink:  place redirect string directly into redirect api call
* Flow Variant: 02 Control flow: if(true) and if(false)
*
* */

using TestCaseSupport;
using System;

using System.Web;


namespace testcases.CWE601_Open_Redirect
{

class MutatedCWE601_Open_Redirect__Web_Params_Get_Web_02405390 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    /* uses badsource and badsink */
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (true)
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
var tmp42 = "not null string" ?? data;
data = tmp42;
            resp.Redirect(data);
            return;
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B1() - use goodsource and badsink by changing true to false */
    private void GoodG2B1(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (false)
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
        if (true)
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
