/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE369_Divide_by_Zero__float_Environment_divide_81_goodB2G.cs
Label Definition File: CWE369_Divide_by_Zero__float.label.xml
Template File: sources-sinks-81_goodB2G.tmpl.cs
*/
/*
 * @description
 * CWE: 369 Divide by zero
 * BadSource: Environment Read data from an environment variable
 * GoodSource: A hardcoded non-zero number (two)
 * Sinks: divide
 *    GoodSink: Check for zero before dividing
 *    BadSink : Dividing by a value that may be zero
 * Flow Variant: 81 Data flow: data passed in a parameter to an abstract method
 *
 * */
#if (!OMITGOOD)

using TestCaseSupport;
using System;

using System.Web;

namespace testcases.CWE369_Divide_by_Zero
{
class CWE369_Divide_by_Zero__float_Environment_divide_81_goodB2G : CWE369_Divide_by_Zero__float_Environment_divide_81_base
{

    public override void Action(float data )
    {
        /* FIX: Check for value of or near zero before dividing */
        if (Math.Abs(data) > 0.000001)
        {
            int result = (int)(100.0 / data);
            IO.WriteLine(result);
        }
        else
        {
            IO.WriteLine("This would result in a divide by zero");
        }
    }
}
}
#endif
