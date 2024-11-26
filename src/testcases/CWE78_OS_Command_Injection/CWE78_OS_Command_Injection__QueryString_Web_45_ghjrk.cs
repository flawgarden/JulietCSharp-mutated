//Original file region: 34, 69, null, null
//Mutated file region: 54, 93, null, null
//CodeQL original results: [78]
//Snyk original results: [78]
//Semgrep original results: []
//Insider original results: []
//-------------
//Semgrep analysis results: []
//CodeQL analysis results: []
//Snyk analysis results: [78]
//Insider analysis results: []
//Original file name: src/testcases/CWE78_OS_Command_Injection/CWE78_OS_Command_Injection__QueryString_Web_45.cs
//Original file CWE's: [78]  
//Original file kind: fail
//Program:
// Mutation info: Insert template from sensitivity/record/record with name nested_record_negative
// Used extensions: 
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using HelperRecords;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE78_OS_Command_Injection__QueryString_Web_45767697.cs
Label Definition File: CWE78_OS_Command_Injection.label.xml
Template File: sources-sink-45.tmpl.cs
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: QueryString_Web Parse id param out of the URL query string (without using getParameter())
 * GoodSource: A hardcoded string
 * Sinks: exec
 *    BadSink : dynamic command execution with Runtime.getRuntime().exec()
 * Flow Variant: 45 Data flow: data passed as a private class member variable from one function to another in the same class
 *
 * */

using TestCaseSupport;
using System;

using System.Diagnostics;
using System.Runtime.InteropServices;

using System.Web;


namespace testcases.CWE78_OS_Command_Injection
{

class MutatedCWE78_OS_Command_Injection__QueryString_Web_45767697 : AbstractTestCaseWeb
{

    private string dataBad;
    private string dataGoodG2B;
#if (!OMITBAD)
    private void BadSink(HttpRequest req, HttpResponse resp)
    {
SimpleRecord first = new SimpleRecord(dataBad);
SimpleRecord second = new SimpleRecord("");
NestedRecord nested = new NestedRecord(first, second);
dataBad = nested.b.t;
        string data = dataBad;
        String osCommand;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            /* running on Windows */
            osCommand = "c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir ";
        }
        else
        {
            /* running on non-Windows */
            osCommand = "/bin/ls ";
        }
        /* POTENTIAL FLAW: command injection */
        Process process = Process.Start(osCommand + data);
        process.WaitForExit();
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
        String osCommand;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            /* running on Windows */
            osCommand = "c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir ";
        }
        else
        {
            /* running on non-Windows */
            osCommand = "/bin/ls ";
        }
        /* POTENTIAL FLAW: command injection */
        Process process = Process.Start(osCommand + data);
        process.WaitForExit();
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
