/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE197_Numeric_Truncation_Error__double_connect_tcp_to_float_53d.cs
Label Definition File: CWE197_Numeric_Truncation_Error__double.label.xml
Template File: sources-sink-53d.tmpl.cs
*/
/*
 * @description
 * CWE: 197 Numeric Truncation Error
 * BadSource: connect_tcp Read data using an outbound tcp connection
 * GoodSource: A hardcoded non-zero, non-min, non-max, even number
 * Sinks: to_float
 *    BadSink : Convert data to a float
 * Flow Variant: 53 Data flow: data passed as an argument from one method through two others to a fourth; all four functions are in different classes in the same package
 *
 * */

using TestCaseSupport;
using System;

namespace testcases.CWE197_Numeric_Truncation_Error
{
class CWE197_Numeric_Truncation_Error__double_connect_tcp_to_float_53d
{
#if (!OMITBAD)
    public static void BadSink(double data )
    {
        {
            /* POTENTIAL FLAW: Convert data to a float, possibly causing a truncation error */
            IO.WriteLine((float)data);
        }
    }
#endif

#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    public static void GoodG2BSink(double data )
    {
        {
            /* POTENTIAL FLAW: Convert data to a float, possibly causing a truncation error */
            IO.WriteLine((float)data);
        }
    }
#endif
}
}
