/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE190_Integer_Overflow__SByte_console_readLine_add_53b.cs
Label Definition File: CWE190_Integer_Overflow.label.xml
Template File: sources-sinks-53b.tmpl.cs
*/
/*
 * @description
 * CWE: 190 Integer Overflow
 * BadSource: console_readLine Read data from the console using readLine
 * GoodSource: A hardcoded non-zero, non-min, non-max, even number
 * Sinks: add
 *    GoodSink: Ensure there will not be an overflow before adding 1 to data
 *    BadSink : Add 1 to data, which can cause an overflow
 * Flow Variant: 53 Data flow: data passed as an argument from one method through two others to a fourth; all four functions are in different classes in the same package
 *
 * */

using TestCaseSupport;
using System;

using System.Web;

namespace testcases.CWE190_Integer_Overflow
{
class CWE190_Integer_Overflow__SByte_console_readLine_add_53b
{
#if (!OMITBAD)
    public static void BadSink(sbyte data )
    {
        CWE190_Integer_Overflow__SByte_console_readLine_add_53c.BadSink(data );
    }
#endif

#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    public static void GoodG2BSink(sbyte data )
    {
        CWE190_Integer_Overflow__SByte_console_readLine_add_53c.GoodG2BSink(data );
    }

    /* goodB2G() - use badsource and goodsink */
    public static void GoodB2GSink(sbyte data )
    {
        CWE190_Integer_Overflow__SByte_console_readLine_add_53c.GoodB2GSink(data );
    }
#endif
}
}
