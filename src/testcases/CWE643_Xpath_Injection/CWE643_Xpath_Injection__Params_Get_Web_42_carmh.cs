using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE643_Xpath_Injection__Params_Get_Web_42382186.cs
Label Definition File: CWE643_Xpath_Injection.label.xml
Template File: sources-sinks-42.tmpl.cs
*/
/*
 * @description
 * CWE: 643 Xpath Injection
 * BadSource: Params_Get_Web Read data from a querystring using Params.Get()
 * GoodSource: A hardcoded string
 * Sinks:
 *    GoodSink: validate input through SecurityElement.Escape
 *    BadSink : user input is used without validate
 * Flow Variant: 42 Data flow: data returned from one method to another in the same class
 *
 * */

using TestCaseSupport;
using System;

using System.Runtime.InteropServices;
using System.Xml.XPath;

using System.Web;


namespace testcases.CWE643_Xpath_Injection
{
class MutatedCWE643_Xpath_Injection__Params_Get_Web_42382186 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    private static string BadSource(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* POTENTIAL FLAW: Read data from a querystring using Params.Get */
        data = req.Params.Get("name");
var map42 = new Dictionary<string, string>();
map42[data] = "const string";
map42.TryAdd(data, data);
data = map42[data];
        return data;
    }

    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data = BadSource(req, resp);
        string xmlFile = null;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            /* running on Windows */
            xmlFile = "..\\..\\CWE643_Xpath_Injection__Helper.xml";
        }
        else
        {
            /* running on non-Windows */
            xmlFile = "../../CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null)
        {
            /* assume username||password as source */
            string[] tokens = data.Split("||".ToCharArray());
            if (tokens.Length < 2)
            {
                return;
            }
            string username = tokens[0];
            string password = tokens[1];
            /* build xpath */
            XPathDocument inputXml = new XPathDocument(xmlFile);
            XPathNavigator xPath = inputXml.CreateNavigator();
            /* INCIDENTAL: CWE180 Incorrect Behavior Order: Validate Before Canonicalize
             *     The user input should be canonicalized before validation. */
            /* POTENTIAL FLAW: user input is used without validate */
            string query = "//users/user[name/text()='" + username +
                           "' and pass/text()='" + password + "']" +
                           "/secret/text()";
            string secret = (string)xPath.Evaluate(query);
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    private static string GoodG2BSource(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
        return data;
    }

    private static void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data = GoodG2BSource(req, resp);
        string xmlFile = null;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            /* running on Windows */
            xmlFile = "..\\..\\CWE643_Xpath_Injection__Helper.xml";
        }
        else
        {
            /* running on non-Windows */
            xmlFile = "../../CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null)
        {
            /* assume username||password as source */
            string[] tokens = data.Split("||".ToCharArray());
            if (tokens.Length < 2)
            {
                return;
            }
            string username = tokens[0];
            string password = tokens[1];
            /* build xpath */
            XPathDocument inputXml = new XPathDocument(xmlFile);
            XPathNavigator xPath = inputXml.CreateNavigator();
            /* INCIDENTAL: CWE180 Incorrect Behavior Order: Validate Before Canonicalize
             *     The user input should be canonicalized before validation. */
            /* POTENTIAL FLAW: user input is used without validate */
            string query = "//users/user[name/text()='" + username +
                           "' and pass/text()='" + password + "']" +
                           "/secret/text()";
            string secret = (string)xPath.Evaluate(query);
        }
    }

    /* goodB2G() - use badsource and goodsink */
    private static string GoodB2GSource(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* POTENTIAL FLAW: Read data from a querystring using Params.Get */
        data = req.Params.Get("name");
        return data;
    }

    private static void GoodB2G(HttpRequest req, HttpResponse resp)
    {
        string data = GoodB2GSource(req, resp);
        string xmlFile = null;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            /* running on Windows */
            xmlFile = "..\\..\\CWE643_Xpath_Injection__Helper.xml";
        }
        else
        {
            /* running on non-Windows */
            xmlFile = "../../CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null)
        {
            /* assume username||password as source */
            string[] tokens = data.Split("||".ToCharArray());
            if (tokens.Length < 2)
            {
                return;
            }
            /* FIX: validate input using StringEscapeUtils */
            string username = System.Security.SecurityElement.Escape(tokens[0]);
            string password = System.Security.SecurityElement.Escape(tokens[1]);
            /* build xpath */
            XPathDocument inputXml = new XPathDocument(xmlFile);
            XPathNavigator xPath = inputXml.CreateNavigator();
            string query = "//users/user[name/text()='" + username +
                           "' and pass/text()='" + password + "']" +
                           "/secret/text()";
            string secret = (string)xPath.Evaluate(query);
        }
    }

    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B(req, resp);
        GoodB2G(req, resp);
    }
#endif //omitgood
}
}
