/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE89_SQL_Injection__Web_QueryString_Web_CommandText_16.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-16.tmpl.cs
*/
/*
* @description
* CWE: 89 SQL Injection
* BadSource: QueryString_Web Parse id param out of the URL query string (without using getParameter())
* GoodSource: A hardcoded string
* Sinks: CommandText
*    GoodSink: Use prepared statement and concatenate CommandText (properly)
*    BadSink : data concatenated into SQL statement used in CommandText, which could result in SQL Injection
* Flow Variant: 16 Control flow: while(true)
*
* */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;
using System.Data;
using System.Web;


namespace testcases.CWE89_SQL_Injection
{
class CWE89_SQL_Injection__Web_QueryString_Web_CommandText_16 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        while (true)
        {
            data = ""; /* initialize data in case id is not in query string */
            /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
            {
                if (req.QueryString["id"] != null)
                {
                    data = req.QueryString["id"];
                }
            }
            break;
        }
        while (true)
        {
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
            break;
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data;
        while (true)
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
            break;
        }
        while (true)
        {
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
            break;
        }
    }

    /* goodB2G() - use badsource and goodsink */
    private void GoodB2G(HttpRequest req, HttpResponse resp)
    {
        string data;
        while (true)
        {
            data = ""; /* initialize data in case id is not in query string */
            /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
            {
                if (req.QueryString["id"] != null)
                {
                    data = req.QueryString["id"];
                }
            }
            break;
        }
        while (true)
        {
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
            break;
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
