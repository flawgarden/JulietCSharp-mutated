using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using HelperStructs;
using System.Runtime.InteropServices;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE78_OS_Command_Injection__QueryString_Web_45113907.cs
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

class MutatedCWE78_OS_Command_Injection__QueryString_Web_45113907 : AbstractTestCaseWeb
{

    private string dataBad;
    private string dataGoodG2B;
#if (!OMITBAD)
    private void BadSink(HttpRequest req, HttpResponse resp)
    {

var structMutated12321 = new SimpleStruct();
var newStruct123 = structMutated12321 with { str = dataBad };
dataBad = newStruct123.str;
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