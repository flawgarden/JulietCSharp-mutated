/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE94_Improper_Control_of_Generation_of_Code__NetClient_81a.cs
Label Definition File: CWE94_Improper_Control_of_Generation_of_Code.label.xml
Template File: sources-sinks-81a.tmpl.cs
*/
/*
 * @description
 * CWE: 94 Improper Control of Generation of Code
 * BadSource: NetClient Read data from a web server with WebClient
 * GoodSource: Set data to an integer represented as a string
 * Sinks:
 *    GoodSink: Validate user input prior to compiling
 *    BadSink : Compile sourceCode containing unvalidated user input
 * Flow Variant: 81 Data flow: data passed in a parameter to an abstract method
 *
 * */

using TestCaseSupport;
using System;

using System.IO;
using System.Net;

namespace testcases.CWE94_Improper_Control_of_Generation_of_Code
{
class CWE94_Improper_Control_of_Generation_of_Code__NetClient_81a : AbstractTestCase
{
#if (!OMITBAD)
    public override void Bad()
    {
        string data;
        data = ""; /* Initialize data */
        /* read input from WebClient */
        {
            try
            {
                using (WebClient client = new WebClient())
                {
                    using (StreamReader sr = new StreamReader(client.OpenRead("http://www.example.org/")))
                    {
                        /* POTENTIAL FLAW: Read data from a web server with WebClient */
                        /* This will be reading the first "line" of the response body,
                        * which could be very long if there are no newlines in the HTML */
                        data = sr.ReadLine();
                    }
                }
            }
            catch (IOException exceptIO)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptIO, "Error with stream reading");
            }
        }
        CWE94_Improper_Control_of_Generation_of_Code__NetClient_81_base baseObject = new CWE94_Improper_Control_of_Generation_of_Code__NetClient_81_bad();
        baseObject.Action(data );
    }
#endif //omitbad
#if (!OMITGOOD)
    public override void Good()
    {
        GoodG2B();
        GoodB2G();
    }

    /* goodG2B() - use GoodSource and BadSink */
    private void GoodG2B()
    {
        string data;
        /* FIX: Set data to an integer represented as a string */
        data = "10";
        CWE94_Improper_Control_of_Generation_of_Code__NetClient_81_base baseObject = new CWE94_Improper_Control_of_Generation_of_Code__NetClient_81_goodG2B();
        baseObject.Action(data );
    }

    /* goodB2G() - use BadSource and GoodSink */
    private void GoodB2G()
    {
        string data;
        data = ""; /* Initialize data */
        /* read input from WebClient */
        {
            try
            {
                using (WebClient client = new WebClient())
                {
                    using (StreamReader sr = new StreamReader(client.OpenRead("http://www.example.org/")))
                    {
                        /* POTENTIAL FLAW: Read data from a web server with WebClient */
                        /* This will be reading the first "line" of the response body,
                        * which could be very long if there are no newlines in the HTML */
                        data = sr.ReadLine();
                    }
                }
            }
            catch (IOException exceptIO)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptIO, "Error with stream reading");
            }
        }
        CWE94_Improper_Control_of_Generation_of_Code__NetClient_81_base baseObject = new CWE94_Improper_Control_of_Generation_of_Code__NetClient_81_goodB2G();
        baseObject.Action(data );
    }
#endif //omitgood
}
}
