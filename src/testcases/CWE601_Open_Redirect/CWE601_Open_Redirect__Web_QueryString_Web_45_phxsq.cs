//Original file region: 31, 72, null, null
//Mutated file region: 51, 95, null, null
//CodeQL original results: [601]
//Snyk original results: [601]
//Semgrep original results: []
//Insider original results: []
//-------------
//Semgrep analysis results: []
//CodeQL analysis results: [563]
//Snyk analysis results: [601]
//Insider analysis results: []
//Original file name: src/testcases/CWE601_Open_Redirect/CWE601_Open_Redirect__Web_QueryString_Web_45.cs
//Original file CWE's: [601]  
//Original file kind: fail
//Mutation info: Insert template from sensitivity/operators/operators with name indexer_custom_two_dim_positive_2 
//Used extensions: 
//Program:
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using HelperOperators;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE601_Open_Redirect__Web_QueryString_Web_45980115.cs
Label Definition File: CWE601_Open_Redirect__Web.label.xml
Template File: sources-sink-45.tmpl.cs
*/
/*
 * @description
 * CWE: 601 Open Redirect
 * BadSource: QueryString_Web Parse id param out of the URL query string (without using getParameter())
 * GoodSource: A hardcoded string
 * Sinks:
 *    BadSink : place redirect string directly into redirect api call
 * Flow Variant: 45 Data flow: data passed as a private class member variable from one function to another in the same class
 *
 * */

using TestCaseSupport;
using System;

using System.Web;


namespace testcases.CWE601_Open_Redirect
{

class MutatedCWE601_Open_Redirect__Web_QueryString_Web_45980115 : AbstractTestCaseWeb
{

    private string dataBad;
    private string dataGoodG2B;
#if (!OMITBAD)
    private void BadSink(HttpRequest req, HttpResponse resp)
    {
        string data = dataBad;
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
        dataBad = data;

var operators1943 = new SpecialOperatorsStringHolder("tdP3k0ujRh4BPf4T47wvDwYOVtu6GGuPhLgjPk8zxYW3M66wrA9Mazk7FAi1FxdLwoeE");
dataBad = operators1943[0, dataBad];
        BadSink(req, resp);
    }
#endif //omitbad
#if (!OMITGOOD)
    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B(req, resp);
    }

    private void GoodG2BSink(HttpRequest req, HttpResponse resp)
    {
        string data = dataGoodG2B;
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

    /* goodG2B() - use goodsource and badsink */
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
        dataGoodG2B = data;
        GoodG2BSink(req, resp);
    }
#endif //omitgood
}
}
