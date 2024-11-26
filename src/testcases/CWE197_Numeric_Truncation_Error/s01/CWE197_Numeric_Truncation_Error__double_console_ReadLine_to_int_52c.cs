/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE197_Numeric_Truncation_Error__double_console_ReadLine_to_int_52c.cs
Label Definition File: CWE197_Numeric_Truncation_Error__double.label.xml
Template File: sources-sink-52c.tmpl.cs
*/
/*
 * @description
 * CWE: 197 Numeric Truncation Error
 * BadSource: console_ReadLine Read data from the console using ReadLine
 * GoodSource: A hardcoded non-zero, non-min, non-max, even number
 * Sinks: to_int
 *    BadSink : Convert data to a int
 * Flow Variant: 52 Data flow: data passed as an argument from one method to another to another in three different classes in the same package
 *
 * */

using TestCaseSupport;
using System;

namespace testcases.CWE197_Numeric_Truncation_Error
{
class CWE197_Numeric_Truncation_Error__double_console_ReadLine_to_int_52c
{
#if (!OMITBAD)
    public static void BadSink(double data )
    {
        {
            /* POTENTIAL FLAW: Convert data to a int, possibly causing a truncation error */
            IO.WriteLine((int)data);
        }
    }
#endif

#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    public static void GoodG2BSink(double data )
    {
        {
            /* POTENTIAL FLAW: Convert data to a int, possibly causing a truncation error */
            IO.WriteLine((int)data);
        }
    }
#endif
}
}
