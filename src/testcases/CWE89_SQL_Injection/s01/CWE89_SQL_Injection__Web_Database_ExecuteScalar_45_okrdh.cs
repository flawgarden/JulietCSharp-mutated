//Original file region: 34, 94, null, null
//Mutated file region: 53, 116, null, null
//Semgrep original results: [89]
//Snyk original results: [89]
//CodeQL original results: []
//Insider original results: []
//-------------
//Semgrep analysis results: [89]
//CodeQL analysis results: []
//Snyk analysis results: []
//Insider analysis results: []
//Original file name: src/testcases/CWE89_SQL_Injection/s01/CWE89_SQL_Injection__Web_Database_ExecuteScalar_45.cs
//Original file CWE's: [89]  
//Original file kind: fail
//Mutation info: Insert template from sensitivity/array with name array_index_from_end_negative 
//Used extensions: 
//Program:
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE89_SQL_Injection__Web_Database_ExecuteScalar_45692349.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-45.tmpl.cs
*/
/*
 * @description
 * CWE: 89 SQL Injection
 * BadSource: Database Read data from a database
 * GoodSource: A hardcoded string
 * Sinks: ExecuteScalar
 *    GoodSink: Use prepared statement and ExecuteScalar() (properly)
 *    BadSink : data concatenated into SQL statement used in ExecuteScalar(), which could result in SQL Injection
 * Flow Variant: 45 Data flow: data passed as a private class member variable from one function to another in the same class
 *
 * */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;
using System.Data;
using System.Web;


namespace testcases.CWE89_SQL_Injection
{
class MutatedCWE89_SQL_Injection__Web_Database_ExecuteScalar_45692349 : AbstractTestCaseWeb
{

    private string dataBad;
    private string dataGoodG2B;
    private string dataGoodB2G;
#if (!OMITBAD)
    private void BadSink(HttpRequest req, HttpResponse resp)
    {
        string data = dataBad;
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

    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        data = ""; /* Initialize data */
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
                            data = dr.GetString(1);
                            var array139418 = new[]{ "EKQdoGidmXZakFIn7rAzJUXc3YOyXzg710Gf0STbRWgxAmE2z9xLtvytxxjP2tFx0cjt8nxoXihxyjbRTV9XBVNGBXsCtEjhQ", "iCV3MMJxKNB4NVS5guswfOdrl4u5T99gGn3O8cwL2hC2AceraICxi6bUjnSRcNeLOeykcD6E7g37LkrIaCeK7M8JLioVJfs", data };
                            data = array139418[^2];
                        }
                    }
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error with SQL statement");
            }
        }
        dataBad = data;
        BadSink(req, resp);
    }
#endif //omitbad
#if (!OMITGOOD)
    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B(req, resp);
        GoodB2G(req, resp);
    }

    private void GoodG2BSink(HttpRequest req, HttpResponse resp)
    {
        string data = dataGoodG2B;
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

    /* goodG2B() - use goodsource and badsink */
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
        dataGoodG2B = data;
        GoodG2BSink(req, resp);
    }

    private void GoodB2GSink(HttpRequest req, HttpResponse resp)
    {
        string data = dataGoodB2G;
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

    /* goodB2G() - use badsource and goodsink */
    private void GoodB2G(HttpRequest req, HttpResponse resp)
    {
        string data;
        data = ""; /* Initialize data */
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
                            data = dr.GetString(1);
                        }
                    }
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, exceptSql, "Error with SQL statement");
            }
        }
        dataGoodB2G = data;
        GoodB2GSink(req, resp);
    }
#endif //omitgood
}
}
