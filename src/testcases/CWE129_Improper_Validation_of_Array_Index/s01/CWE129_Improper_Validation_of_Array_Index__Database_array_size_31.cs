/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE129_Improper_Validation_of_Array_Index__Database_array_size_31.cs
Label Definition File: CWE129_Improper_Validation_of_Array_Index.label.xml
Template File: sources-sinks-31.tmpl.cs
*/
/*
 * @description
 * CWE: 129 Improper Validation of Array Index
 * BadSource: Database Read data from a database
 * GoodSource: A hardcoded non-zero, non-min, non-max, even number
 * Sinks: array_size
 *    GoodSink: data is used to set the size of the array and it must be greater than 0
 *    BadSink : data is used to set the size of the array, but it could be set to 0
 * Flow Variant: 31 Data flow: make a copy of data within the same method
 *
 * */

using TestCaseSupport;
using System;

using System.Web;

using Microsoft.Data.SqlClient;

namespace testcases.CWE129_Improper_Validation_of_Array_Index
{
class CWE129_Improper_Validation_of_Array_Index__Database_array_size_31 : AbstractTestCase
{
#if (!OMITBAD)
    public override void Bad()
    {
        int dataCopy;
        {
            int data;
            data = int.MinValue; /* Initialize data */
            /* Read data from a database */
            {
                try
                {
                    /* setup the connection */
                    using (SqlConnection connection = IO.GetDBConnection())
                    {
                        connection.Open();
                        /* prepare and execute a (hardcoded) query */
                        using (SqlCommand command = new SqlCommand(null, connection))
                        {
                            command.CommandText = "select name from users where id=0";
                            command.Prepare();
                            using (SqlDataReader dr = command.ExecuteReader())
                            {
                                /* POTENTIAL FLAW: Read data from a database query SqlDataReader */
                                string stringNumber = dr.GetString(1);
                                if (stringNumber != null) /* avoid NPD incidental warnings */
                                {
                                    try
                                    {
                                        data = int.Parse(stringNumber.Trim());
                                    }
                                    catch (FormatException exceptNumberFormat)
                                    {
                                        IO.Logger.Log(NLog.LogLevel.Warn, exceptNumberFormat, "Number format exception parsing data from string");
                                    }
                                }
                            }
                        }
                    }
                }
                catch (SqlException exceptSql)
                {
                    IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error with SQL statement");
                }
            }
            dataCopy = data;
        }
        {
            int data = dataCopy;
            int[] array = null;
            /* POTENTIAL FLAW: Verify that data is non-negative, but still allow it to be 0 */
            if (data >= 0)
            {
                array = new int[data];
            }
            else
            {
                IO.WriteLine("Array size is negative");
            }
            /* do something with the array */
            array[0] = 5;
            IO.WriteLine(array[0]);
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    public override void Good()
    {
        GoodG2B();
        GoodB2G();
    }

    /* goodG2B() - use goodsource and badsink */
    private void GoodG2B()
    {
        int dataCopy;
        {
            int data;
            /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
            data = 2;
            dataCopy = data;
        }
        {
            int data = dataCopy;
            int[] array = null;
            /* POTENTIAL FLAW: Verify that data is non-negative, but still allow it to be 0 */
            if (data >= 0)
            {
                array = new int[data];
            }
            else
            {
                IO.WriteLine("Array size is negative");
            }
            /* do something with the array */
            array[0] = 5;
            IO.WriteLine(array[0]);
        }
    }

    /* goodB2G() - use badsource and goodsink */
    private void GoodB2G()
    {
        int dataCopy;
        {
            int data;
            data = int.MinValue; /* Initialize data */
            /* Read data from a database */
            {
                try
                {
                    /* setup the connection */
                    using (SqlConnection connection = IO.GetDBConnection())
                    {
                        connection.Open();
                        /* prepare and execute a (hardcoded) query */
                        using (SqlCommand command = new SqlCommand(null, connection))
                        {
                            command.CommandText = "select name from users where id=0";
                            command.Prepare();
                            using (SqlDataReader dr = command.ExecuteReader())
                            {
                                /* POTENTIAL FLAW: Read data from a database query SqlDataReader */
                                string stringNumber = dr.GetString(1);
                                if (stringNumber != null) /* avoid NPD incidental warnings */
                                {
                                    try
                                    {
                                        data = int.Parse(stringNumber.Trim());
                                    }
                                    catch (FormatException exceptNumberFormat)
                                    {
                                        IO.Logger.Log(NLog.LogLevel.Warn, exceptNumberFormat, "Number format exception parsing data from string");
                                    }
                                }
                            }
                        }
                    }
                }
                catch (SqlException exceptSql)
                {
                    IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error with SQL statement");
                }
            }
            dataCopy = data;
        }
        {
            int data = dataCopy;
            /* Need to ensure that the array is of size > 3  and < 101 due to the GoodSource and the large_fixed BadSource */
            int[] array = null;
            /* FIX: Verify that data is non-negative AND greater than 0 */
            if (data > 0)
            {
                array = new int[data];
            }
            else
            {
                IO.WriteLine("Array size is negative");
            }
            /* do something with the array */
            array[0] = 5;
            IO.WriteLine(array[0]);
        }
    }
#endif //omitgood
}
}
