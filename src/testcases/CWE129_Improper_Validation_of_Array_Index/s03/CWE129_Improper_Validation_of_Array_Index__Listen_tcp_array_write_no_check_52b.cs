/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE129_Improper_Validation_of_Array_Index__Listen_tcp_array_write_no_check_52b.cs
Label Definition File: CWE129_Improper_Validation_of_Array_Index.label.xml
Template File: sources-sinks-52b.tmpl.cs
*/
/*
 * @description
 * CWE: 129 Improper Validation of Array Index
 * BadSource: Listen_tcp Read data using a listening tcp connection
 * GoodSource: A hardcoded non-zero, non-min, non-max, even number
 * Sinks: array_write_no_check
 *    GoodSink: Write to array after verifying index
 *    BadSink : Write to array without any verification of index
 * Flow Variant: 52 Data flow: data passed as an argument from one method to another to another in three different classes in the same package
 *
 * */

using TestCaseSupport;
using System;

using System.Web;

namespace testcases.CWE129_Improper_Validation_of_Array_Index
{
class CWE129_Improper_Validation_of_Array_Index__Listen_tcp_array_write_no_check_52b
{
#if (!OMITBAD)
    public static void BadSink(int data )
    {
        CWE129_Improper_Validation_of_Array_Index__Listen_tcp_array_write_no_check_52c.BadSink(data );
    }
#endif

#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    public static void GoodG2BSink(int data )
    {
        CWE129_Improper_Validation_of_Array_Index__Listen_tcp_array_write_no_check_52c.GoodG2BSink(data );
    }

    /* goodB2G() - use badsource and goodsink */
    public static void GoodB2GSink(int data )
    {
        CWE129_Improper_Validation_of_Array_Index__Listen_tcp_array_write_no_check_52c.GoodB2GSink(data );
    }
#endif
}
}
