//Original file region: 30, 81, null, null
//Mutated file region: 60, 114, null, null
//Semgrep original results: [89]
//CodeQL original results: [89]
//Snyk original results: [89]
//Insider original results: []
//-------------
//Semgrep analysis results: [89]
//CodeQL analysis results: [835]
//Snyk analysis results: []
//Insider analysis results: []
//Original file name: src/testcases/CWE89_SQL_Injection/s02/CWE89_SQL_Injection__Web_QueryString_Web_ExecuteNonQuery_02.cs
//Original file CWE's: [89]  
//Original file kind: fail
//Mutation info: Insert template from sensitivity/operators/staticAbstract with name static_abstract_reversed_store_negative 
//Used extensions: 
//Program:
using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using HelperOperators;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE89_SQL_Injection__Web_QueryString_Web_ExecuteNonQuery_02160140.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-02.tmpl.cs
*/
/*
* @description
* CWE: 89 SQL Injection
* BadSource: QueryString_Web Parse id param out of the URL query string (without using getParameter())
* GoodSource: A hardcoded string
* Sinks: ExecuteNonQuery
*    GoodSink: Use prepared statement and ExecuteNonQuery (properly)
*    BadSink : data concatenated into SQL statement used in ExecuteNonQuery(), which could result in SQL Injection
* Flow Variant: 02 Control flow: if(true) and if(false)
*
* */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;
using System.Data;
using System.Web;


namespace testcases.CWE89_SQL_Injection
{
class MutatedCWE89_SQL_Injection__Web_QueryString_Web_ExecuteNonQuery_02160140 : AbstractTestCaseWeb
{
#if (!OMITBAD)

public static T OuterSAIGetter<T>(bool b) where T : StaticAbstractInterface<T>
{
    return b ? T.ATProperty : T.GetEmptyT();
}

public static T VirtualizedVGet<T>(bool b) where T : StaticAbstractInterface<T>
{
    return T.VGetInner(b);
}
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (true)
        {
            data = ""; /* initialize data in case id is not in query string */
            /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
            {
                if (req.QueryString["id"] != null)
                {
                    data = req.QueryString["id"];
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }
        if (true)

SAIReversed.ATProperty = new(data);
data = SAIReversed.VGetInner(true).value;
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
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B1() - use goodsource and badsink by changing first true to false */
    private void GoodG2B1(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (false)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }
        else
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
        }
        if (true)
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

    /* GoodG2B2() - use goodsource and badsink by reversing statements in first if */
    private void GoodG2B2(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (true)
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }
        if (true)
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

    /* goodB2G1() - use badsource and goodsink by changing second true to false */
    private void GoodB2G1(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (true)
        {
            data = ""; /* initialize data in case id is not in query string */
            /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
            {
                if (req.QueryString["id"] != null)
                {
                    data = req.QueryString["id"];
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }
        if (false)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
            IO.WriteLine("Benign, fixed string");
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

    /* goodB2G2() - use badsource and goodsink by reversing statements in second if  */
    private void GoodB2G2(HttpRequest req, HttpResponse resp)
    {
        string data;
        if (true)
        {
            data = ""; /* initialize data in case id is not in query string */
            /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
            {
                if (req.QueryString["id"] != null)
                {
                    data = req.QueryString["id"];
                }
            }
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }
        if (true)
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
        GoodG2B1(req, resp);
        GoodG2B2(req, resp);
        GoodB2G1(req, resp);
        GoodB2G2(req, resp);
    }
#endif //omitgood
}
}
