/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE89_SQL_Injection__Web_Database_ExecuteScalar_66b.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-66b.tmpl.cs
*/
/*
 * @description
 * CWE: 89 SQL Injection
 * BadSource: Database Read data from a database
 * GoodSource: A hardcoded string
 * Sinks: ExecuteScalar
 *    GoodSink: Use prepared statement and ExecuteScalar() (properly)
 *    BadSink : data concatenated into SQL statement used in ExecuteScalar(), which could result in SQL Injection
 * Flow Variant: 66 Data flow: data passed in an array from one method to another in different source files in the same package
 *
 * */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;
using System.Data;
using System.Web;

namespace testcases.CWE89_SQL_Injection
{
class CWE89_SQL_Injection__Web_Database_ExecuteScalar_66b
{
#if (!OMITBAD)
    public static void BadSink(string[] dataArray , HttpRequest req, HttpResponse resp)
    {
        string data = dataArray[2];
        try
        {
            using (SqlConnection dbConnection = IO.GetDBConnection())
            {
                dbConnection.Open();
                using (SqlCommand badSqlCommand = new SqlCommand(null, dbConnection))
                {
                    /* POTENTIAL FLAW: data concatenated into SQL statement used in ExecuteScalar(), which could result in SQL Injection */
                    badSqlCommand.CommandText = "select * from users where name='" +data+"'";
                    object firstCol = badSqlCommand.ExecuteScalar();
                    if (firstCol != null)
                    {
                        IO.WriteLine(firstCol.ToString()); /* Use ResultSet in some way */
                    }
                }
            }
        }
        catch (SqlException exceptSql)
        {
            IO.Logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
        }
    }
#endif

#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    public static void GoodG2BSink(string[] dataArray , HttpRequest req, HttpResponse resp)
    {
        string data = dataArray[2];
        try
        {
            using (SqlConnection dbConnection = IO.GetDBConnection())
            {
                dbConnection.Open();
                using (SqlCommand badSqlCommand = new SqlCommand(null, dbConnection))
                {
                    /* POTENTIAL FLAW: data concatenated into SQL statement used in ExecuteScalar(), which could result in SQL Injection */
                    badSqlCommand.CommandText = "select * from users where name='" +data+"'";
                    object firstCol = badSqlCommand.ExecuteScalar();
                    if (firstCol != null)
                    {
                        IO.WriteLine(firstCol.ToString()); /* Use ResultSet in some way */
                    }
                }
            }
        }
        catch (SqlException exceptSql)
        {
            IO.Logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
        }
    }

    /* goodB2G() - use badsource and goodsink */
    public static void GoodB2GSink(string[] dataArray , HttpRequest req, HttpResponse resp)
    {
        string data = dataArray[2];
        try
        {
            using (SqlConnection dbConnection = IO.GetDBConnection())
            {
                dbConnection.Open();
                using (SqlCommand goodSqlCommand = new SqlCommand(null, dbConnection))
                {
                    /* FIX: Use prepared statement and concatenate ExecuteScalar() (properly) */
                    SqlParameter nameParam = new SqlParameter("@name", SqlDbType.VarChar, 100);
                    nameParam.Value = data;
                    goodSqlCommand.CommandText += "select * from users where name=@name";
                    goodSqlCommand.Prepare();
                    object firstCol = goodSqlCommand.ExecuteScalar();
                    if (firstCol != null)
                    {
                        IO.WriteLine(firstCol.ToString()); /* Use ResultSet in some way */
                    }
                }
            }
        }
        catch (SqlException exceptSql)
        {
            IO.Logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
        }
    }
#endif
}
}
