//Original file region: 30, 115, null, null
//Mutated file region: 50, 138, null, null
//Semgrep original results: [89]
//CodeQL original results: [89]
//Snyk original results: []
//Insider original results: []
//-------------
//Semgrep analysis results: [89]
//CodeQL analysis results: []
//Snyk analysis results: [89]
//Insider analysis results: []
//Original file name: src/testcases/CWE89_SQL_Injection/s01/CWE89_SQL_Injection__Web_Get_Cookies_Web_ExecuteNonQuery_12.cs
//Original file CWE's: [89]  
//Original file kind: fail
//Mutation info: Insert template from sensitivity/collections/map with name map_simple_get_1_negative 
//Used extensions: 
//Program:
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE89_SQL_Injection__Web_Get_Cookies_Web_ExecuteNonQuery_12887554.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-12.tmpl.cs
*/
/*
* @description
* CWE: 89 SQL Injection
* BadSource: Get_Cookies_Web Read data from the first cookie using Cookies
* GoodSource: A hardcoded string
* Sinks: ExecuteNonQuery
*    GoodSink: Use prepared statement and ExecuteNonQuery (properly)
*    BadSink : data concatenated into SQL statement used in ExecuteNonQuery(), which could result in SQL Injection
* Flow Variant: 12 Control flow: if(IO.StaticReturnsTrueOrFalse())
*
* */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;
using System.Data;
using System.Web;


namespace testcases.CWE89_SQL_Injection
{
class MutatedCWE89_SQL_Injection__Web_Get_Cookies_Web_ExecuteNonQuery_12887554 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        if(IO.StaticReturnsTrueOrFalse())
        {
            data = ""; /* initialize data in case there are no cookies */
            /* Read data from cookies */
            {
                HttpCookieCollection cookieSources = req.Cookies;
                if (cookieSources != null)
                {
                    /* POTENTIAL FLAW: Read data from the first cookie value */
                    data = cookieSources[0].Value;
                }
            }
        }
        else
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
        }
var map42 = new Dictionary<string, string>();
map42[data] = "const string";
data = map42[data];
        if(IO.StaticReturnsTrueOrFalse())
        {
            int? result = null;
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    dbConnection.Open();
                    using (SqlCommand badSqlCommand = new SqlCommand(null, dbConnection))
                    {
                        /* POTENTIAL FLAW: data concatenated into SQL statement used in ExecuteNonQuery(), which could result in SQL Injection */
                        badSqlCommand.CommandText = "insert into users (status) values ('updated') where name='" +data+"'";
                        result = badSqlCommand.ExecuteNonQuery();
                        if (result != null)
                        {
                            IO.WriteLine("Name, " + data +", updated successfully");
                        }
                        else
                        {
                            IO.WriteLine("Unable to update records for user: " + data);
                        }
                    }
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
            }
        }
        else
        {
            int? result = null;
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    dbConnection.Open();
                    using (SqlCommand goodSqlCommand = new SqlCommand(null, dbConnection))
                    {
                        goodSqlCommand.CommandText = "insert into users (status) values ('updated') where name=@name";
                        /* FIX: Use prepared statement and ExecuteNonQuery (properly) */
                        SqlParameter nameParam = new SqlParameter("@name", SqlDbType.VarChar, 0);
                        nameParam.Value = data;
                        goodSqlCommand.Parameters.Add(nameParam);
                        goodSqlCommand.Prepare();
                        result = goodSqlCommand.ExecuteNonQuery();
                        if (result != null)
                        {
                            IO.WriteLine("Name, " + data +", updated successfully");
                        }
                        else
                        {
                            IO.WriteLine("Unable to update records for user: " + data);
                        }
                    }
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
            }
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink by changing the first "if" so that
     * both branches use the GoodSource */
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data;
        if(IO.StaticReturnsTrueOrFalse())
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
        }
        else
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
        }
        if(IO.StaticReturnsTrueOrFalse())
        {
            int? result = null;
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    dbConnection.Open();
                    using (SqlCommand badSqlCommand = new SqlCommand(null, dbConnection))
                    {
                        /* POTENTIAL FLAW: data concatenated into SQL statement used in ExecuteNonQuery(), which could result in SQL Injection */
                        badSqlCommand.CommandText = "insert into users (status) values ('updated') where name='" +data+"'";
                        result = badSqlCommand.ExecuteNonQuery();
                        if (result != null)
                        {
                            IO.WriteLine("Name, " + data +", updated successfully");
                        }
                        else
                        {
                            IO.WriteLine("Unable to update records for user: " + data);
                        }
                    }
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
            }
        }
        else
        {
            int? result = null;
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    dbConnection.Open();
                    using (SqlCommand badSqlCommand = new SqlCommand(null, dbConnection))
                    {
                        /* POTENTIAL FLAW: data concatenated into SQL statement used in ExecuteNonQuery(), which could result in SQL Injection */
                        badSqlCommand.CommandText = "insert into users (status) values ('updated') where name='" +data+"'";
                        result = badSqlCommand.ExecuteNonQuery();
                        if (result != null)
                        {
                            IO.WriteLine("Name, " + data +", updated successfully");
                        }
                        else
                        {
                            IO.WriteLine("Unable to update records for user: " + data);
                        }
                    }
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
            }
        }
    }

    /* goodB2G() - use badsource and goodsink by changing the second "if" so that
     * both branches use the GoodSink */
    private void GoodB2G(HttpRequest req, HttpResponse resp)
    {
        string data;
        if(IO.StaticReturnsTrueOrFalse())
        {
            data = ""; /* initialize data in case there are no cookies */
            /* Read data from cookies */
            {
                HttpCookieCollection cookieSources = req.Cookies;
                if (cookieSources != null)
                {
                    /* POTENTIAL FLAW: Read data from the first cookie value */
                    data = cookieSources[0].Value;
                }
            }
        }
        else
        {
            data = ""; /* initialize data in case there are no cookies */
            /* Read data from cookies */
            {
                HttpCookieCollection cookieSources = req.Cookies;
                if (cookieSources != null)
                {
                    /* POTENTIAL FLAW: Read data from the first cookie value */
                    data = cookieSources[0].Value;
                }
            }
        }
        if(IO.StaticReturnsTrueOrFalse())
        {
            int? result = null;
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    dbConnection.Open();
                    using (SqlCommand goodSqlCommand = new SqlCommand(null, dbConnection))
                    {
                        goodSqlCommand.CommandText = "insert into users (status) values ('updated') where name=@name";
                        /* FIX: Use prepared statement and ExecuteNonQuery (properly) */
                        SqlParameter nameParam = new SqlParameter("@name", SqlDbType.VarChar, 0);
                        nameParam.Value = data;
                        goodSqlCommand.Parameters.Add(nameParam);
                        goodSqlCommand.Prepare();
                        result = goodSqlCommand.ExecuteNonQuery();
                        if (result != null)
                        {
                            IO.WriteLine("Name, " + data +", updated successfully");
                        }
                        else
                        {
                            IO.WriteLine("Unable to update records for user: " + data);
                        }
                    }
                }
            }
            catch (SqlException exceptSql)
            {
                IO.Logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
            }
        }
        else
        {
            int? result = null;
            try
            {
                using (SqlConnection dbConnection = IO.GetDBConnection())
                {
                    dbConnection.Open();
                    using (SqlCommand goodSqlCommand = new SqlCommand(null, dbConnection))
                    {
                        goodSqlCommand.CommandText = "insert into users (status) values ('updated') where name=@name";
                        /* FIX: Use prepared statement and ExecuteNonQuery (properly) */
                        SqlParameter nameParam = new SqlParameter("@name", SqlDbType.VarChar, 0);
                        nameParam.Value = data;
                        goodSqlCommand.Parameters.Add(nameParam);
                        goodSqlCommand.Prepare();
                        result = goodSqlCommand.ExecuteNonQuery();
                        if (result != null)
                        {
                            IO.WriteLine("Name, " + data +", updated successfully");
                        }
                        else
                        {
                            IO.WriteLine("Unable to update records for user: " + data);
                        }
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
