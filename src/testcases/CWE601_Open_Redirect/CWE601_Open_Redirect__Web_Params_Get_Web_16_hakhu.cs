//Original file region: 27, 59, null, null
//Mutated file region: 48, 90, null, null
//CodeQL original results: [601]
//Snyk original results: [601]
//Semgrep original results: []
//Insider original results: []
//-------------
//Semgrep analysis results: []
//CodeQL analysis results: [563]
//Snyk analysis results: [601]
//Insider analysis results: []
//Original file name: src/testcases/CWE601_Open_Redirect/CWE601_Open_Redirect__Web_Params_Get_Web_16.cs
//Original file CWE's: [601]  
//Original file kind: fail
//Mutation info: Insert template from sensitivity/dynamic with name dynamic_binding_exception_positive 
//Used extensions: 
//Program:
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using HelperFields;
using Microsoft.CSharp.RuntimeBinder;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE601_Open_Redirect__Web_Params_Get_Web_16817375.cs
Label Definition File: CWE601_Open_Redirect__Web.label.xml
Template File: sources-sink-16.tmpl.cs
*/
/*
* @description
* CWE: 601 Open Redirect
* BadSource: Params_Get_Web Read data from a querystring using Params.Get()
* GoodSource: A hardcoded string
* BadSink:  place redirect string directly into redirect api call
* Flow Variant: 16 Control flow: while(true)
*
* */

using TestCaseSupport;
using System;

using System.Web;


namespace testcases.CWE601_Open_Redirect
{

class MutatedCWE601_Open_Redirect__Web_Params_Get_Web_16817375 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    /* uses badsource and badsink */
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        while (true)
        {
            /* POTENTIAL FLAW: Read data from a querystring using Params.Get */
            data = req.Params.Get("name");

try
{
    dynamic dynamic9871 = new StringHolder(data);
    data = dynamic9871.value;
}
catch (RuntimeBinderException _)
{
    data = "gjOKEym7S";
}
            break;
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
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data;
        while (true)
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
            break;
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
