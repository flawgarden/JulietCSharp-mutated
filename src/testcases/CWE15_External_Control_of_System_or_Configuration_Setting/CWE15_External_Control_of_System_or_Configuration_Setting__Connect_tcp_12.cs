/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE15_External_Control_of_System_or_Configuration_Setting__Connect_tcp_12.cs
Label Definition File: CWE15_External_Control_of_System_or_Configuration_Setting.label.xml
Template File: sources-sink-12.tmpl.cs
*/
/*
* @description
* CWE: 15 External Control of System or Configuration Setting
* BadSource: Connect_tcp Read data using an outbound tcp connection
* GoodSource: A hardcoded string
* BadSink:  Set the catalog name with the value of data
* Flow Variant: 12 Control flow: if(IO.StaticReturnsTrueOrFalse())
*
* */

using TestCaseSupport;
using System;

using Microsoft.Data.SqlClient;

using System.Web;

using System.IO;
using System.Net.Sockets;

namespace testcases.CWE15_External_Control_of_System_or_Configuration_Setting
{

class CWE15_External_Control_of_System_or_Configuration_Setting__Connect_tcp_12 : AbstractTestCase
{
#if (!OMITBAD)
    /* uses badsource and badsink - see how tools report flaws that don't always occur */
    public override void Bad()
    {
        string data;
        if (IO.StaticReturnsTrueOrFalse())
        {
            data = ""; /* Initialize data */
            /* Read data using an outbound tcp connection */
            {
                try
                {
                    /* Read data using an outbound tcp connection */
                    using (TcpClient tcpConn = new TcpClient("host.example.org", 39544))
                    {
                        /* read input from socket */
                        using (StreamReader sr = new StreamReader(tcpConn.GetStream()))
                        {
                            /* POTENTIAL FLAW: Read data using an outbound tcp connection */
                            data = sr.ReadLine();
                        }
                    }
                }
                catch (IOException exceptIO)
                {
                    IO.Logger.Log(NLog.LogLevel.Warn, exceptIO, "Error with stream reading");
                }
            }
        }
        else
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
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
    /* goodG2B() - use goodsource and badsink by changing the "if" so that
     * both branches use the GoodSource */
    private void GoodG2B()
    {
        string data;
        if (IO.StaticReturnsTrueOrFalse())
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
        }
        else
        {
            /* FIX: Use a hardcoded string */
            data = "foo";
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
