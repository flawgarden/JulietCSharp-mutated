/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE89_SQL_Injection__Web_Params_Get_Web_CommandText_42.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-42.tmpl.cs
*/
/*
 * @description
 * CWE: 89 SQL Injection
 * BadSource: Params_Get_Web Read data from a querystring using Params.Get()
 * GoodSource: A hardcoded string
 * Sinks: CommandText
 *    GoodSink: Use prepared statement and concatenate CommandText (properly)
 *    BadSink : data concatenated into SQL statement used in CommandText, which could result in SQL Injection
 * Flow Variant: 42 Data flow: data returned from one method to another in the same class
 *
 * */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;
using System.Data;
using System.Web;


namespace testcases.CWE89_SQL_Injection
{
class CWE89_SQL_Injection__Web_Params_Get_Web_CommandText_42 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    private static string BadSource(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* POTENTIAL FLAW: Read data from a querystring using Params.Get */
        data = req.Params.Get("name");
        return data;
    }

    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data = BadSource(req, resp);
        if (data != null)
        {
            string[] names = data.Split('-');
            int successCount = 0;
            SqlCommand badSqlCommand = null;
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    badSqlCommand.Connection = dbConnection;
                    dbConnection.Open();
                    for (int i = 0; i < names.Length; i++)
                    {
                        /* POTENTIAL FLAW: data concatenated into SQL statement used in CommandText, which could result in SQL Injection */
                        badSqlCommand.CommandText += "update users set hitcount=hitcount+1 where name='" + names[i] + "';";
                    }
                    var affectedRows = badSqlCommand.ExecuteNonQuery();
                    successCount += affectedRows;
                    IO.WriteLine("Succeeded in " + successCount + " out of " + names.Length + " queries.");
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
            }
            finally
            {
                try
                {
                    if (badSqlCommand != null)
                    {
                        badSqlCommand.Dispose();
                    }
                }
                catch (SqlException exceptSql)
                {
                    IO.Logger.Log(NLog.LogLevel.Warn, "Error disposing SqlCommand", exceptSql);
                }
            }
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    private static string GoodG2BSource(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
        return data;
    }

    private static void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data = GoodG2BSource(req, resp);
        if (data != null)
        {
            string[] names = data.Split('-');
            int successCount = 0;
            SqlCommand badSqlCommand = null;
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    badSqlCommand.Connection = dbConnection;
                    dbConnection.Open();
                    for (int i = 0; i < names.Length; i++)
                    {
                        /* POTENTIAL FLAW: data concatenated into SQL statement used in CommandText, which could result in SQL Injection */
                        badSqlCommand.CommandText += "update users set hitcount=hitcount+1 where name='" + names[i] + "';";
                    }
                    var affectedRows = badSqlCommand.ExecuteNonQuery();
                    successCount += affectedRows;
                    IO.WriteLine("Succeeded in " + successCount + " out of " + names.Length + " queries.");
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
            }
            finally
            {
                try
                {
                    if (badSqlCommand != null)
                    {
                        badSqlCommand.Dispose();
                    }
                }
                catch (SqlException exceptSql)
                {
                    IO.Logger.Log(NLog.LogLevel.Warn, "Error disposing SqlCommand", exceptSql);
                }
            }
        }
    }

    /* goodB2G() - use badsource and goodsink */
    private static string GoodB2GSource(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* POTENTIAL FLAW: Read data from a querystring using Params.Get */
        data = req.Params.Get("name");
        return data;
    }

    private static void GoodB2G(HttpRequest req, HttpResponse resp)
    {
        string data = GoodB2GSource(req, resp);
        if (data != null)
        {
            string[] names = data.Split('-');
            int successCount = 0;
            try
            {
                /* FIX: Use prepared statement and concatenate CommandText (properly) */
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    dbConnection.Open();
                    using (SqlCommand goodSqlCommand = new SqlCommand(null, dbConnection))
                    {
                        for (int i = 0; i < names.Length; i++)
                        {
                            SqlParameter nameParam = new SqlParameter("@name", SqlDbType.VarChar, 100);
                            nameParam.Value = names[i];
                            goodSqlCommand.CommandText += "update users set hitcount=hitcount+1 where name=@name;";
                        }
                        goodSqlCommand.Prepare();
                        int affectedRows = goodSqlCommand.ExecuteNonQuery();
                        successCount += affectedRows;
                        IO.WriteLine("Succeeded in " + successCount + " out of " + names.Length + " queries.");
                    }
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
            }
        }
    }

    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B(req, resp);
        GoodB2G(req, resp);
    }
#endif //omitgood
}
}
