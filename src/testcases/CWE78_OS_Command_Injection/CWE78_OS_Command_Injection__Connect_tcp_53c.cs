/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__Connect_tcp_53c.cs
Label Definition File: CWE78_OS_Command_Injection.label.xml
Template File: sources-sink-53c.tmpl.cs
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: Connect_tcp Read data using an outbound tcp connection
 * GoodSource: A hardcoded string
 * Sinks: exec
 *    BadSink : dynamic command execution with Runtime.getRuntime().exec()
 * Flow Variant: 53 Data flow: data passed as an argument from one method through two others to a fourth; all four functions are in different classes in the same package
 *
 * */

using TestCaseSupport;
using System;

using System.Web;

namespace testcases.CWE78_OS_Command_Injection
{
class CWE78_OS_Command_Injection__Connect_tcp_53c
{
#if (!OMITBAD)
    public static void BadSink(string data )
    {
        CWE78_OS_Command_Injection__Connect_tcp_53d.BadSink(data );
    }
#endif

#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    public static void GoodG2BSink(string data )
    {
        CWE78_OS_Command_Injection__Connect_tcp_53d.GoodG2BSink(data );
    }
#endif
}
}
