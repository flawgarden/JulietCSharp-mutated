/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE15_External_Control_of_System_or_Configuration_Setting__Listen_tcp_67b.cs
Label Definition File: CWE15_External_Control_of_System_or_Configuration_Setting.label.xml
Template File: sources-sink-67b.tmpl.cs
*/
/*
 * @description
 * CWE: 15 External Control of System or Configuration Setting
 * BadSource: Listen_tcp Read data using a listening tcp connection
 * GoodSource: A hardcoded string
 * Sinks:
 *    BadSink : Set the catalog name with the value of data
 * Flow Variant: 67 Data flow: data passed in a class from one method to another in different source files in the same package
 *
 * */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;

using System.Web;

namespace testcases.CWE15_External_Control_of_System_or_Configuration_Setting
{
class CWE15_External_Control_of_System_or_Configuration_Setting__Listen_tcp_67b
{
#if (!OMITBAD)
    public static void BadSink(CWE15_External_Control_of_System_or_Configuration_Setting__Listen_tcp_67a.Container dataContainer )
    {
        string data = dataContainer.containerOne;
        SqlConnection dbConnection = null;
        try
        {
            dbConnection = IO.GetDBConnection();
            /* POTENTIAL FLAW: Set the database user name with the value of data
             * allowing unauthorized access to a portion of the DB */
            dbConnection.ConnectionString = @"Data Source=" + "" + ";Initial Catalog=" + "" + ";User ID=" + data + ";Password=" + "";
            dbConnection.Open();
        }
        catch (SqlException exceptSql)
        {
            IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error getting database connection");
        }
        finally
        {
            try
            {
                if (dbConnection != null)
                {
                    dbConnection.Close();
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error closing Connection");
            }
        }
    }
#endif

#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    public static void GoodG2BSink(CWE15_External_Control_of_System_or_Configuration_Setting__Listen_tcp_67a.Container dataContainer )
    {
        string data = dataContainer.containerOne;
        SqlConnection dbConnection = null;
        try
        {
            dbConnection = IO.GetDBConnection();
            /* POTENTIAL FLAW: Set the database user name with the value of data
             * allowing unauthorized access to a portion of the DB */
            dbConnection.ConnectionString = @"Data Source=" + "" + ";Initial Catalog=" + "" + ";User ID=" + data + ";Password=" + "";
            dbConnection.Open();
        }
        catch (SqlException exceptSql)
        {
            IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error getting database connection");
        }
        finally
        {
            try
            {
                if (dbConnection != null)
                {
                    dbConnection.Close();
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error closing Connection");
            }
        }
    }
#endif
}
}
