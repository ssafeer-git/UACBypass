using System.ServiceProcess;
using System.Timers;
using MySql.Data.MySqlClient;
using System;
using System.Threading;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;
using System.Reflection;
using System.Linq;
using System.Collections.Generic;

namespace Toolkit
{
    public partial class ElevatorService : ServiceBase
    {
        Thread _thread;
        bool KeepLooping = true;
        MySqlConnection connection = null;
        MySqlCommand command = null;
        string DBHost, DBName, Username, Password, URI;
        string id = null;
        string NRCAN_UserID = "";
        bool BlackListedAppRequested = false;
        bool MD5HashNotFound = false;
        bool debug;
        List<string> BlackListedPaths;
        System.Collections.Generic.List<BlackListedHashes> BLPrograms;
        public ElevatorService()
        {
            InitializeComponent();
            BLPrograms = new System.Collections.Generic.List<BlackListedHashes>();
        }

        enum Logs
        {
            emergency = 0,
            alert = 1,
            critical = 2,
            error = 3,
            warning = 4,
            notice = 5,
            info = 5,
            debug = 6
        }

        protected override void OnStart(string[] args)
        {

            _thread = new Thread(new ThreadStart(ProcessPendingRequests));
            _thread.Start();
        }

        protected override void OnStop()
        {
            KeepLooping = false;
            if (connection != null)
            {
                if (connection.State == System.Data.ConnectionState.Open)
                {
                    connection.Close();
                    connection.Dispose();
                }
            }
        }

        public void ProcessPendingRequests()
        {

            string ip = null;
            try
            {
                string version = Assembly.GetExecutingAssembly().GetName().Version.ToString();
                
                WriteToFile("Starting Service...");
                WriteToFile("Service Version:" + version);
                WriteToFile("Getting System IP Address");
                ip = GetLocalIPAddress();
                WriteToFile("Computer IP Address:" + ip);

                WriteToFile("Getting System32 Hashes");
                GetSystem32Hashes();
                WriteToFile("Hashes Obtained");

                //LOAD DATABASE PARAMTERS FROM WEB SERVICE
                WriteToFile("Loading Starting Parameters");
                LoadParams();
                WriteToFile("Parameters Loaded Sucessfully... Host:" + DBHost + ", Database:" + DBName + ", Username:" + Username + ", Password:1800-F***-U, URI:" + URI + ", Debug:" + debug.ToString());

                connection = new MySqlConnection("SERVER=" + DBHost + ";DATABASE=" + DBName + ";UID=" + Username + ";PASSWORD=" + Password + ";");
                WriteToFile("Successfully Opened A Connection With DB");

                //IF NO EXCEPTIONS THEN ADD DEBUG LOGS IN DATABASE
                //LOG ALL DETAILS IN DB
                AddDebugLogs(connection, Logs.debug, "Elevator service started on: " + ip);
                AddDebugLogs(connection, Logs.debug, "Service Version:" + version);
                AddDebugLogs(connection, Logs.debug, "System32 hashes loaded sucessfully on " + ip);
                AddDebugLogs(connection, Logs.debug, "Start up parameters loaded successfully on " + ip + "... Host:" + DBHost + ", Database:" + DBName + ", Username:" + Username + ", Password:1800-F***-U, URI:" + URI + ", Debug:" + debug.ToString());
                AddDebugLogs(connection, Logs.debug, "Successfully opened a connection with db on " + ip);

            }
            catch (Exception ex)
            {
                WriteToFile(ex.Message);
            }

            while (KeepLooping)
            {
                //ONLY CONTINUE IF THESE HOURS ARE SATISFIED
                if (DateTime.Now.Hour < 17 && DateTime.Now.Hour > 6)
                {
                    try
                    {

                        if (connection.State == System.Data.ConnectionState.Closed)
                        {
                            connection.Open();
                        }

                        string query = "Select Username,Workstation, AppPath,RequestedDate,AppName,id,token from ElevateProcess where Workstation = '" + ip + "' and PermissionGranted = 1 and status = 'open'";
                        command = new MySqlCommand(query, connection);
                        MySqlDataAdapter Reader = new MySqlDataAdapter(command);
                        System.Data.DataTable Data = new System.Data.DataTable();
                        Reader.Fill(Data);
                        Reader.Dispose();
                        if (Data.Rows.Count > 0)
                        {
                            ProcessIFValidRequest(Data);
                        }

                    }
                    catch (Exception ex)
                    {
                        WriteToFile(ex.Message);
                    }
                    finally
                    {
                        connection.Close();
                        connection.Dispose();
                    }
                }
                System.Threading.Thread.Sleep(30000);
            }
        }

        private void AddLogs(MySqlConnection connection, Logs log, string id, string message)
        {
            try
            {
                if (connection.State == System.Data.ConnectionState.Closed)
                {
                    connection.Open();
                }
                //REMOVE QUOTES FROM STRING IF ANY
                message = message.Replace("'", "");
                message = message.Replace("\\", "\\\\");
                string query = "insert into log (level,timestamp,message) VALUES ('" + log.ToString() + "','" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "','" + "Request " + id + " " + message + "')";
                MySqlCommand command = new MySqlCommand(query, connection);
                command.ExecuteNonQuery();
                message = message.Replace("\\\\", "\\");
                //UPDATE THE STATUS TO ERROR AND CLOSE THE REQUEST IF PASSED IN LOG VALUE WAS ERROR
                if (log == Logs.error)
                {
                    query = "update ElevateProcess set status = '" + Logs.error + "' where id = " + id;
                    command = new MySqlCommand(query, connection);
                    command.ExecuteNonQuery();
                    connection.Close();
                    //SEND A FRIENDLY MESSAGE TO CLIENT
                    if (MD5HashNotFound)
                    {
                        MD5HashNotFound = false;
                        message = "We cannot verify the source of requested application, try again later";
                    }

                    if (BlackListedAppRequested)
                    {
                        BlackListedAppRequested = false;
                        message = "You are trying to install an application that is not permitted by your network administrator";
                    }

                    SendNotification(log.ToString(), NRCAN_UserID, GetLocalIPAddress(), message);
                }

            }
            catch (Exception ex)
            {
                WriteToFile(ex.Message);
            }
        }

        private void AddDebugLogs(MySqlConnection connection, Logs LogLevel, string message)
        {
            if (LogLevel == Logs.debug && debug)
            {
                if (connection.State == System.Data.ConnectionState.Closed)
                {
                    connection.Open();
                }
                //REMOVE QUOTES FROM STRING IF ANY
                message = message.Replace("'", "");
                message = message.Replace("\\", "\\\\");
                string query = "insert into log (level,timestamp,message) VALUES ('" + LogLevel.ToString() + "','" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "','" + message + "')";
                MySqlCommand command = new MySqlCommand(query, connection);
                command.ExecuteNonQuery();
            }
        }

        public void WriteToFile(string contents)
        {
            StreamWriter sw = new StreamWriter(@"C:\Temp\ServiceLogs.txt", true);
            sw.WriteLine(DateTime.Now.ToString() + ": " + contents);
            sw.Close();
        }

        public string GetLocalIPAddress()
        {
            string ipAddress = null;
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    ipAddress = ip.ToString().Trim();
                }
            }



            return ipAddress;
        }

        private void LoadParams()
        {

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://intranet.nofc.cfs.nrcan.gc.ca/software/config");
            request.Method = "GET";
            request.Proxy = null;
            request.UserAgent = "IE";
            request.Credentials = new System.Net.NetworkCredential("service", "SerenityNow1972");
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            System.IO.StreamReader reader = new StreamReader(response.GetResponseStream());
            string source = reader.ReadToEnd();
            response.Close();
            reader.Close();
            //PARSE JSON
            var controller = new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<ParamController>(source);
            DBHost = controller.host;
            Username = controller.user;
            Password = controller.pass;
            URI = controller.uri;
            DBName = controller.name;
            debug = controller.debug;


        }

        public string MD5(string s)
        {
            using (var provider = System.Security.Cryptography.MD5.Create())
            {
                StringBuilder builder = new StringBuilder();

                foreach (byte b in provider.ComputeHash(Encoding.UTF8.GetBytes(s)))
                    builder.Append(b.ToString("x2").ToLower());

                return builder.ToString();
            }
        }

        public void ProcessIFValidRequest(System.Data.DataTable Data)
        {
            try
            {

                string workstation, apppath, appname, tokentocompare;
                DateTime date = DateTime.Now;
                string salt = "SerenityNow1972";
                string sep = "<>";
                string input = "";
                string MyToken = "";
                string ProgramHash = "";
                StringBuilder sb = null;
                System.Collections.Generic.List<string> vals;
                foreach (System.Data.DataRow row in Data.Rows)
                {
                    sb = new StringBuilder();

                    vals = new System.Collections.Generic.List<string>();

                    vals.Add(salt);

                    NRCAN_UserID = row["Username"].ToString();
                    vals.Add(NRCAN_UserID);

                    workstation = row["Workstation"].ToString();
                    vals.Add(workstation);

                    apppath = row["AppPath"].ToString();
                    vals.Add(apppath);
                    date = DateTime.Parse(row["RequestedDate"].ToString());
                    string reqdate = date.ToString("yyyy-MM-dd HH:mm:ss");
                    vals.Add(reqdate);

                    appname = row["AppName"].ToString();
                    id = row["id"].ToString();

                    WriteToFile("Processing Request " + id);
                    AddDebugLogs(connection, Logs.debug, "Processing request " + id + " on " + workstation);


                    sb.Append("Username: " + NRCAN_UserID);
                    sb.Append(", Workstation: " + workstation);
                    sb.Append(", Application Name: " + appname);
                    sb.Append(", Application Path: " + apppath);
                    sb.Append(", Requested Date: " + reqdate);
                    input = string.Join(sep, vals);
                    sb.Append(", MD5 Hash Algorithm Value: " + input);
                    MyToken = MD5(input);
                    sb.Append(", MD5 Hash Value: " + MyToken);
                    tokentocompare = row["token"].ToString();
                    sb.Append(", Token In Database: " + tokentocompare);

                    //GET THE HASH OF PROGRAM
                    ProgramHash = GetSHAHashFromFile(apppath);
                    sb.Append(", SHA256 Hash: " + ProgramHash);
                    //CHECK THAT THIS PROGRAM HASH DOESN'T MATCH THE BLACK LISTED HASH
                    BlackListedHashes program = BLPrograms.Find((x => x.SHA256Hash.Equals(ProgramHash)));
                    //NULL MEANS GOOD ELSE POSSIBLE HACK ATTEMP
                    if (program == null)
                    {
                        sb.Append(", Message: Successful validation against blacklisted program hashes");
                        //IF TOKEN MATCHD THEN GO AHEAD AND ELEVATE THE PROCESS, ELSE DIDN'T MATCH PROBABLY AN HACK ATTEMPT OR SOME OTHER ERROR HAPPENED
                        if (MyToken.Equals(tokentocompare))
                        {
                            sb.Append(", Message: MD5 hash validation was successful");
                            // launch the application
                            ApplicationLoader.PROCESS_INFORMATION procInfo;
                            ApplicationLoader.StartProcessAndBypassUAC(apppath, out procInfo);
                            //ONCE THE APPLICATIOIN HAS BEEN LAUNCHED UPDATE THE RECORD
                            string query = "Update ElevateProcess Set Status = 'closed' where id = " + id;
                            command = new MySqlCommand(query, connection);
                            command.ExecuteNonQuery();
                            AddLogs(connection, Logs.info, id, " process spawned successfully on " + workstation);
                            WriteToFile("Request " + id.ToLower() + " Successfully processed");
                            connection.Close();
                            break;
                        }
                        else
                        {
                            sb.Append(", Message: MD5 hash validation failed");
                            MD5HashNotFound = true;
                            AddLogs(connection, Logs.error, id, "MD5 hash mismatch (possible hack attempt), Client Name: " + NRCAN_UserID + " , Application Name: " + appname + " , Application Path: " + apppath);
                            break;
                        }
                    }
                    else
                    {
                        sb.Append(", Message: SHA256 validation failed, this is a blacklisted application");
                        BlackListedAppRequested = true;
                        AddLogs(connection, Logs.error, id, "Client " + NRCAN_UserID + " requested a black listed app, Application Name: " + appname + " , Application Path: " + apppath);
                        break;
                    }


                }
                //ADD DEBUG INFO
                if (debug && sb != null)
                {
                    AddLogs(connection, Logs.debug, id, sb.ToString());
                }
            }
            catch (Exception ex)
            {
                AddLogs(connection, Logs.error, id, ex.Message);
                WriteToFile(ex.Message);
            }
        }

        private string GetSHAHashFromFile(string name)
        {
            string value = null;
            try
            {
                using (var sha = SHA256.Create())
                {
                    using (var stream = File.OpenRead(name))
                    {
                        value = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
                    }
                }
            }
            catch (Exception ex)
            {
                WriteToFile(ex.Message);
            }
            return value;
        }

        private void GetSystem32Hashes()
        {
            var info = new DirectoryInfo(@"C:\Windows\System32");
            FileInfo[] files = info.GetFiles("*.*");
            string hash = null;
            foreach (var file in files)
            {

                try
                {
                    hash = GetSHAHashFromFile(file.FullName);
                    if (!string.IsNullOrEmpty(hash))
                    {
                        BLPrograms.Add(new BlackListedHashes(file.Name, hash));
                    }
                }
                catch (Exception ex) { }

            }
        }

        private void SendNotification(string eventname, string userid, string ip, string message)
        {
            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(URI + "/notify-user");
                request.Method = "POST";
                request.ContentType = "application/x-www-form-urlencoded";
                string postdata = "event=" + eventname + "&message=" + message + "&user=" + userid + "&ip=" + ip + "&token=7809862876-je";
                request.Proxy = null;
                byte[] bytes = System.Text.ASCIIEncoding.ASCII.GetBytes(postdata);
                Stream stream = request.GetRequestStream();
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush();
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                response.Close();
            }
            catch (WebException ex)
            {
                HttpWebResponse res = ex.Response as HttpWebResponse;
                StreamReader reader = new StreamReader(res.GetResponseStream());
                string exception = reader.ReadToEnd();
                WriteToFile(exception);

            }

        }

    }


}
