//Original file region: 30, 56, null, null
//Mutated file region: 50, 78, null, null
//CodeQL original results: [78]
//Snyk original results: [78]
//Semgrep original results: []
//Insider original results: []
//-------------
//Semgrep analysis results: []
//CodeQL analysis results: [78, 88]
//Snyk analysis results: []
//Insider analysis results: []
//Original file name: src/testcases/CWE78_OS_Command_Injection/CWE78_OS_Command_Injection__Params_Get_Web_16.cs
//Original file CWE's: [78]  
//Original file kind: fail
//Program:
// Mutation info: Insert template from sensitivity/virtuality/class with name derived_binary_op2_positive
// Used extensions: 
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using HelperClasses;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE78_OS_Command_Injection__Params_Get_Web_16387729.cs
Label Definition File: CWE78_OS_Command_Injection.label.xml
Template File: sources-sink-16.tmpl.cs
*/
/*
* @description
* CWE: 78 OS Command Injection
* BadSource: Params_Get_Web Read data from a querystring using Params.Get()
* GoodSource: A hardcoded string
* BadSink: exec dynamic command execution with Runtime.getRuntime().exec()
* Flow Variant: 16 Control flow: while(true)
*
* */

using TestCaseSupport;
using System;

using System.Diagnostics;
using System.Runtime.InteropServices;

using System.Web;


namespace testcases.CWE78_OS_Command_Injection
{

class MutatedCWE78_OS_Command_Injection__Params_Get_Web_16387729 : AbstractTestCaseWeb
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
BaseBinaryOpClass a12341 = new DerivedBinaryOpClass2();
data = a12341.VirtualCall("", data);
            break;
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
        GoodG2B(req, resp);
    }
#endif //omitgood
}
}
