using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using HelperThreads;
using System.Threading;
/* TEMPLATE GENERATED TESTCASE FILE
Filename: MutatedCWE89_SQL_Injection__Web_Database_ExecuteScalar_17259576.cs
Label Definition File: CWE89_SQL_Injection__Web.label.xml
Template File: sources-sinks-17.tmpl.cs
*/
/*
* @description
* CWE: 89 SQL Injection
* BadSource: Database Read data from a database
* GoodSource: A hardcoded string
* Sinks: ExecuteScalar
*    GoodSink: Use prepared statement and ExecuteScalar() (properly)
*    BadSink : data concatenated into SQL statement used in ExecuteScalar(), which could result in SQL Injection
* Flow Variant: 17 Control flow: for loops
*
* */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;
using System.Data;
using System.Web;


namespace testcases.CWE89_SQL_Injection
{
class MutatedCWE89_SQL_Injection__Web_Database_ExecuteScalar_17259576 : AbstractTestCaseWeb
{
#if (!OMITBAD)
    public override void Bad(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* We need to have one source outside of a for loop in order
         * to prevent the compiler from generating an error because
         * data is uninitialized
         */
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
        for (int j = 0; j < 1; j++)
        {
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
Wrapper<string> w = new Wrapper<string>(data);
var task1 = new SwitchingTask(w, data);
var task2 = new SwitchingTask(w, data);
Thread thread1 = new Thread(task1.run);
Thread thread2 = new Thread(task2.run);
thread1.Start();
thread2.Start();
try {
  thread1.Join();
} catch (ThreadInterruptedException e) {
}
try {
  thread2.Join();
} catch (ThreadInterruptedException e) {
}
data = w.i;
                IO.Logger.Log(NLog.LogLevel.Warn, "Error getting database connection", exceptSql);
            }
        }
    }
#endif //omitbad
#if (!OMITGOOD)
    /* goodG2B() - use goodsource and badsink */
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
        string data;
        /* FIX: Use a hardcoded string */
        data = "foo";
        for (int j = 0; j < 1; j++)
        {
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
    }

    /* goodB2G() - use badsource and goodsink*/
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
        for (int k = 0; k < 1; k++)
        {
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
    }

    public override void Good(HttpRequest req, HttpResponse resp)
    {
        GoodG2B(req, resp);
        GoodB2G(req, resp);
    }
#endif //omitgood
}
}
