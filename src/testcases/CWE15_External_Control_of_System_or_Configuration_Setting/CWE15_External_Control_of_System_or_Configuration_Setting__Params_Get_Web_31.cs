/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE15_External_Control_of_System_or_Configuration_Setting__Params_Get_Web_31.cs
Label Definition File: CWE15_External_Control_of_System_or_Configuration_Setting.label.xml
Template File: sources-sink-31.tmpl.cs
*/
/*
 * @description
 * CWE: 15 External Control of System or Configuration Setting
 * BadSource: Params_Get_Web Read data from a querystring using Params.Get()
 * GoodSource: A hardcoded string
 * Sinks:
 *    BadSink : Set the catalog name with the value of data
 * Flow Variant: 31 Data flow: make a copy of data within the same method
 *
 * */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;

using System.Web;


namespace testcases.CWE15_External_Control_of_System_or_Configuration_Setting
{

class CWE15_External_Control_of_System_or_Configuration_Setting__Params_Get_Web_31 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    /* uses badsource and badsink */
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string dataCopy;
        {
            string data;
            /* POTENTIAL FLAW: Read data from a querystring using Params.Get */
            data = req.Params.Get("name");
            dataCopy = data;
        }
        {
            string data = dataCopy;
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
    }
#endif //omitbad
#if (!OMITGOOD)
    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B(req, resp);
    }

    /* goodG2B() - use goodsource and badsink */
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string dataCopy;
        {
            string data;
            /* FIX: Use a hardcoded string */
            data = "foo";
            dataCopy = data;
        }
        {
            string data = dataCopy;
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
    }
#endif //omitgood
}
}
