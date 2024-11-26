/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE427_Uncontrolled_Search_Path_Element__QueryString_Web_81_goodG2B.cs
Label Definition File: CWE427_Uncontrolled_Search_Path_Element.label.xml
Template File: sources-sink-81_goodG2B.tmpl.cs
*/
/*
 * @description
 * CWE: 427 Uncontrolled Search Path Element
 * BadSource: QueryString_Web Parse id param out of the URL query string (without using getParameter())
 * GoodSource: Use a hardcoded path
 * Sinks: Environment
 *    BadSink :
 * Flow Variant: 81 Data flow: data passed in a parameter to an abstract method
 *
 * */
#if (!OMITGOOD)

using TestCaseSupport;
using System;

using System.Web;
using System.Runtime.InteropServices;

namespace testcases.CWE427_Uncontrolled_Search_Path_Element
{
class CWE427_Uncontrolled_Search_Path_Element__QueryString_Web_81_goodG2B : CWE427_Uncontrolled_Search_Path_Element__QueryString_Web_81_base
{

    public override void Action(string data , HttpRequest req, HttpResponse resp)
    {
        /* POTENTIAL FLAW: Set a new environment variable with a path that is possibly insecure */
        Environment.SetEnvironmentVariable("PATH", data);
    }
}
}
#endif
