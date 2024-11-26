using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using HelperClasses;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE78_OS_Command_Injection__QueryString_Web_13605398.cs
Label Definition File: CWE78_OS_Command_Injection.label.xml
Template File: sources-sink-13.tmpl.cs
*/
/*
* @description
* CWE: 78 OS Command Injection
* BadSource: QueryString_Web Parse id param out of the URL query string (without using getParameter())
* GoodSource: A hardcoded string
* BadSink: exec dynamic command execution with Runtime.getRuntime().exec()
* Flow Variant: 13 Control flow: if(IO.STATIC_READONLY_FIVE==5) and if(IO.STATIC_READONLY_FIVE!=5)
*
* */

using TestCaseSupport;
using System;

using System.Diagnostics;
using System.Runtime.InteropServices;

using System.Web;


namespace testcases.CWE78_OS_Command_Injection
{

class MutatedCWE78_OS_Command_Injection__QueryString_Web_13605398 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    /* uses badsource and badsink */

private static string InterfaceConstrainedMethod<T>(string l, string r) where T : BinaryOpInterface, new()
{
    var tmpWorker = new T();
    return tmpWorker.InterfaceCall(l, r);
}

private static string InheritanceConstrainedMethod<T, V>(string l, string r)
    where T : V, new()
    where V : BaseBinaryOpClass
{
    var tmpWorker = new T();
    return tmpWorker.VirtualCall(l, r);
}
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (IO.STATIC_READONLY_FIVE == 5)
        {
            data = ""; /* initialize data in case id is not in query string */
            /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
            {
                if (req.QueryString["id"] != null)
                {
                    data = req.QueryString["id"];

data = InterfaceConstrainedMethod<ImplBinaryOpInterfaceClass1>(data, "X4F");
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }
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
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B1() - use goodsource and badsink by changing IO.STATIC_READONLY_FIVE==5 to IO.STATIC_READONLY_FIVE!=5 */
    private void GoodG2B1(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (IO.STATIC_READONLY_FIVE != 5)
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

    /* GoodG2B2() - use goodsource and badsink by reversing statements in if */
    private void GoodG2B2(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (IO.STATIC_READONLY_FIVE == 5)
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

    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B1(req, resp);
        GoodG2B2(req, resp);
    }
#endif //omitgood
}
}
