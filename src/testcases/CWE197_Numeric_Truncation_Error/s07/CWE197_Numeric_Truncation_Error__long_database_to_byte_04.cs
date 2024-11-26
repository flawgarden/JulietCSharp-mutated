/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE197_Numeric_Truncation_Error__long_database_to_byte_04.cs
Label Definition File: CWE197_Numeric_Truncation_Error__long.label.xml
Template File: sources-sink-04.tmpl.cs
*/
/*
* @description
* CWE: 197 Numeric Truncation Error
* BadSource: database Read data from a database
* GoodSource: A hardcoded non-zero, non-min, non-max, even number
* BadSink: to_byte Convert data to a byte
* Flow Variant: 04 Control flow: if(PRIVATE_CONST_TRUE) and if(PRIVATE_CONST_FALSE)
*
* */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;

namespace testcases.CWE197_Numeric_Truncation_Error
{

class CWE197_Numeric_Truncation_Error__long_database_to_byte_04 : AbstractTestCase
{

    /* The two variables below are declared "const", so a tool should
     * be able to identify that reads of these will always return their
     * initialized values.
     */
    private const bool PRIVATE_CONST_TRUE = true;
    private const bool PRIVATE_CONST_FALSE = false;
#if (!OMITBAD)
    /* uses badsource and badsink */
    public override void Bad()
    {
        long data;
        if (PRIVATE_CONST_TRUE)
        {
            data = long.MinValue; /* Initialize data */
            /* Read data from a database */
            {
                SqlConnection connection = null;
                SqlDataReader dr = null;
                try
                {
                    /* setup the connection */
                    using (connection = IO.GetDBConnection())
                    {
                        connection.Open();
                        /* prepare and execute a (hardcoded) query */
                        SqlCommand command = new SqlCommand(null, connection);
                        command.CommandText = "select name from users where id=0";
                        command.Prepare();
                        dr = command.ExecuteReader();
                        /* FLAW: Read data from a database query SqlDataReader */
                        string stringNumber = dr.GetString(1);
                        if (stringNumber != null) /* avoid NPD incidental warnings */
                        {
                            try
                            {
                                data = long.Parse(stringNumber.Trim());
                            }
                            catch (FormatException exceptNumberFormat)
                            {
                                IO.Logger.Log(NLog.LogLevel.Warn, exceptNumberFormat, "Number format exception parsing data from string");
                            }
                        }
                    }
                }
                catch (SqlException exceptSql)
                {
                    IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error with SQL statement");
                }
                finally
                {
                    /* Close database objects */
                    try
                    {
                        if (dr != null)
                        {
                            dr.Close();
                        }
                    }
                    catch (Exception except) /* INCIDENTAL: CWE 396 Catch Generic Exception */
                    {
                        IO.Logger.Log(NLog.LogLevel.Warn, except, "Error closing SqlDataReader");
                    }

                    try
                    {
                        if (connection != null)
                        {
                            connection.Close();
                        }
                    }
                    catch (SqlException exceptSql)
                    {
                        IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error closing Connection");
                    }
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = 0L;
        }
        {
            /* POTENTIAL FLAW: Convert data to a byte, possibly causing a truncation error */
            IO.WriteLine((byte)data);
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B1() - use goodsource and badsink by changing PRIVATE_CONST_TRUE to PRIVATE_CONST_FALSE */
    private void GoodG2B1()
    {
        long data;
        if (PRIVATE_CONST_FALSE)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = 0L;
        }
        else
        {
            /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
            data = 2;
        }
        {
            /* POTENTIAL FLAW: Convert data to a byte, possibly causing a truncation error */
            IO.WriteLine((byte)data);
        }
    }

    /* GoodG2B2() - use goodsource and badsink by reversing statements in if */
    private void GoodG2B2()
    {
        long data;
        if (PRIVATE_CONST_TRUE)
        {
            /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
            data = 2;
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = 0L;
        }
        {
            /* POTENTIAL FLAW: Convert data to a byte, possibly causing a truncation error */
            IO.WriteLine((byte)data);
        }
    }

    public override void Good()
    {
        GoodG2B1();
        GoodG2B2();
    }
#endif //omitgood
}
}
