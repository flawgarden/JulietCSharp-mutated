/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE15_External_Control_of_System_or_Configuration_Setting__Environment_16.cs
Label Definition File: CWE15_External_Control_of_System_or_Configuration_Setting.label.xml
Template File: sources-sink-16.tmpl.cs
*/
/*
* @description
* CWE: 15 External Control of System or Configuration Setting
* BadSource: Environment Read data from an environment variable
* GoodSource: A hardcoded string
* BadSink:  Set the catalog name with the value of data
* Flow Variant: 16 Control flow: while(true)
*
* */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;

using System.Web;

namespace testcases.CWE15_External_Control_of_System_or_Configuration_Setting
{

class CWE15_External_Control_of_System_or_Configuration_Setting__Environment_16 : AbstractTestCase
{
#if (!OMITBAD)
    /* uses badsource and badsink */
    public override void Bad()
    {
        string data;
        while (true)
        {
            /* get environment variable ADD */
            /* POTENTIAL FLAW: Read data from an environment variable */
            data = Environment.GetEnvironmentVariable("ADD");
            break;
        }
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
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    private void GoodG2B()
    {
        string data;
        while (true)
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
            break;
        }
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

    public override void Good()
    {
        GoodG2B();
    }
#endif //omitgood
}
}
