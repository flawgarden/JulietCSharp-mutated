/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE190_Integer_Overflow__int_max_multiply_21.cs
Label Definition File: CWE190_Integer_Overflow__int.label.xml
Template File: sources-sinks-21.tmpl.cs
*/
/*
 * @description
 * CWE: 190 Integer Overflow
 * BadSource: max Set data to the maximum value for int
 * GoodSource: A hardcoded non-zero, non-min, non-max, even number
 * Sinks: multiply
 *    GoodSink: Ensure there will not be an overflow before multiplying data by 2
 *    BadSink : If data is positive, multiply by 2, which can cause an overflow
 * Flow Variant: 21 Control flow: Flow controlled by value of a private variable. All functions contained in one file.
 *
 * */

using TestCaseSupport;
using System;

using System.Web;

namespace testcases.CWE190_Integer_Overflow
{
class CWE190_Integer_Overflow__int_max_multiply_21 : AbstractTestCase
{

    /* The variable below is used to drive control flow in the sink function */
    private bool badPrivate = false;
#if (!OMITBAD)
    public override void Bad()
    {
        int data;
        /* POTENTIAL FLAW: Use the maximum value for this type */
        data = int.MaxValue;
        badPrivate = true;
        BadSink(data );
    }

    private void BadSink(int data )
    {
        if (badPrivate)
        {
            if(data > 0) /* ensure we won't have an underflow */
            {
                /* POTENTIAL FLAW: if (data*2) > int.MaxValue, this will overflow */
                int result = (int)(data * 2);
                IO.WriteLine("result: " + result);
            }
        }
    }
#endif //omitbad
    /* The variables below are used to drive control flow in the sink functions. */
    private bool goodB2G1Private = false;
    private bool goodB2G2Private = false;
    private bool goodG2BPrivate = false;
#if (!OMITGOOD)
    public override void Good()
    {
        GoodB2G1();
        GoodB2G2();
        GoodG2B();
    }

    /* goodB2G1() - use BadSource and GoodSink by setting the variable to false instead of true */
    private void GoodB2G1()
    {
        int data;
        /* POTENTIAL FLAW: Use the maximum value for this type */
        data = int.MaxValue;
        goodB2G1Private = false;
        GoodB2G1Sink(data );
    }

    private void GoodB2G1Sink(int data )
    {
        if (goodB2G1Private)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
            IO.WriteLine("Benign, fixed string");
        }
        else
        {
            if(data > 0) /* ensure we won't have an underflow */
            {
                /* FIX: Add a check to prevent an overflow from occurring */
                if (data < (int.MaxValue/2))
                {
                    int result = (int)(data * 2);
                    IO.WriteLine("result: " + result);
                }
                else
                {
                    IO.WriteLine("data value is too large to perform multiplication.");
                }
            }
        }
    }

    /* goodB2G2() - use BadSource and GoodSink by reversing the blocks in the if in the sink function */
    private void GoodB2G2()
    {
        int data;
        /* POTENTIAL FLAW: Use the maximum value for this type */
        data = int.MaxValue;
        goodB2G2Private = true;
        GoodB2G2Sink(data );
    }

    private void GoodB2G2Sink(int data )
    {
        if (goodB2G2Private)
        {
            if(data > 0) /* ensure we won't have an underflow */
            {
                /* FIX: Add a check to prevent an overflow from occurring */
                if (data < (int.MaxValue/2))
                {
                    int result = (int)(data * 2);
                    IO.WriteLine("result: " + result);
                }
                else
                {
                    IO.WriteLine("data value is too large to perform multiplication.");
                }
            }
        }
    }

    /* goodG2B() - use GoodSource and BadSink */
    private void GoodG2B()
    {
        int data;
        /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
        data = 2;
        goodG2BPrivate = true;
        GoodG2BSink(data );
    }

    private void GoodG2BSink(int data )
    {
        if (goodG2BPrivate)
        {
            if(data > 0) /* ensure we won't have an underflow */
            {
                /* POTENTIAL FLAW: if (data*2) > int.MaxValue, this will overflow */
                int result = (int)(data * 2);
                IO.WriteLine("result: " + result);
            }
        }
    }
#endif //omitgood
}
}
