/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE89_SQL_Injection__Web_Connect_tcp_CommandText_68b.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-68b.tmpl.cs
*/
/*
 * @description
 * CWE: 89 SQL Injection
 * BadSource: Connect_tcp Read data using an outbound tcp connection
 * GoodSource: A hardcoded string
 * Sinks: CommandText
 *    GoodSink: Use prepared statement and concatenate CommandText (properly)
 *    BadSink : data concatenated into SQL statement used in CommandText, which could result in SQL Injection
 * Flow Variant: 68 Data flow: data passed as a member variable in the "a" class, which is used by a method in another class in the same package
 *
 * */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;
using System.Data;
using System.Web;

namespace testcases.CWE89_SQL_Injection
{
class CWE89_SQL_Injection__Web_Connect_tcp_CommandText_68b
{
#if (!OMITBAD)
    public static void BadSink(HttpRequest req, HttpResponse resp)
    {
        string data = CWE89_SQL_Injection__Web_Connect_tcp_CommandText_68a.data;
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
#endif

#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    public static void GoodG2BSink(HttpRequest req, HttpResponse resp)
    {
        string data = CWE89_SQL_Injection__Web_Connect_tcp_CommandText_68a.data;
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
    public static void GoodB2GSink(HttpRequest req, HttpResponse resp)
    {
        string data = CWE89_SQL_Injection__Web_Connect_tcp_CommandText_68a.data;
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
#endif
}
}
