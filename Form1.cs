using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Specialized;
using System.IO; // File Loading
using System.Diagnostics; // Process Listing
using System.Security.Cryptography; // MD5
using System.Net; // Connecting to API
using System.Text.RegularExpressions; // Stripping Strings
using System.Diagnostics;
using System.Net;

namespace Malware_Scanner
{
    public struct LinkItem
    {
        public string Href;
        public string Text;
        
        public override string ToString()
        {
            return Href + "\n\t" + Text;
        }
    }

    static class LinkFinder
    {
        public static List<LinkItem> Find(string file)
        {
            List<LinkItem> list = new List<LinkItem>();

            // 1.
            // Find all matches in file.
            MatchCollection m1 = Regex.Matches(file, @"(<a.*?>.*?</a>)",
                RegexOptions.Singleline);

            // 2.
            // Loop over each match.
            foreach (Match m in m1)
            {
                string value = m.Groups[1].Value;
                LinkItem i = new LinkItem();

                // 3.
                // Get href attribute.
                Match m2 = Regex.Match(value, @"href=\""(.*?)\""",
                RegexOptions.Singleline);
                if (m2.Success)
                {
                    i.Href = m2.Groups[1].Value;
                }

                // 4.
                // Remove inner tags from text.
                string t = Regex.Replace(value, @"\s*<.*?>\s*", "",
                RegexOptions.Singleline);
                i.Text = t;

                list.Add(i);
            }
            return list;
        }
    }

    public partial class scannerForm : Form
    {
        private string apiKey = "32b5c878c388a403131b0c95ea75fc44002e77b66fc2bca3c4aebd04e46a32a6"; // VirusTotal API Key
        private string username = "alsmadi";
        private string password = "farahHAMZA1";
        static string inputFilename = "";
        string results = "https://www.virustotal.com/api/get_file_report.json"; // VirusTotal File Report Page
        string results1 = "https://www.virustotal.com/api/scan_url.json";
        public scannerForm()
        {
            InitializeComponent(); // Initialize Form Elements
        }

        private string[] optimizerProProcesses = new string[1]; // Processes run by Optimizer Pro
        private string[] myPCBackupProcesses = new string[1]; // Processes run by MyPC Backup
        private string[] searchProtectProcesses = new string[2]; // Processes run by Search Protect
        private string[] pcHelper360Processes = new string[1]; // Processes run by PC Helper 360

        private void scannerForm_Load(object sender, EventArgs e) // On Form Load Add Processes to Arrays
        {
            optimizerProProcesses[0] = "OptimizerPro";

            myPCBackupProcesses[0] = "BackupStack";

            searchProtectProcesses[0] = "cltmngui";
            searchProtectProcesses[1] = "CltMngSvc";

            pcHelper360Processes[0] = "pch360";
        }

        Dictionary<string, MalwareReport> scannedItems = new Dictionary<string, MalwareReport>(); // Items that have already been scanned (added later to stop same files being re-scanned)
        private void scanButton_Click(object sender, EventArgs e) // On Scan button clicked
        {
            startScan(); // Do menial starting tasks
            Process[] processlist = Process.GetProcesses(); // Get all processes

            foreach (Process process in processlist) // Cycle through all processes
            {
                Console.WriteLine("Process: {0} ID: {1}", process.ProcessName, process.Id); // Debug - Print to Visual Studio Console
                
                if (optimizerProProcesses.Contains(process.ProcessName) && scanFile(process.Modules[0].FileName)) // If Optimizer Pro Process and VirusTotal says it is not safe
                    fileDetected("Optimizer Pro", process.Modules[0].FileName); // Report the file was detected
                if (myPCBackupProcesses.Contains(process.ProcessName) && scanFile(process.Modules[0].FileName)) // If MyPC Backup Process and VirusTotal says it is not safe
                    fileDetected("MyPC Backup", process.Modules[0].FileName); // Report the file was detected
                if (searchProtectProcesses.Contains(process.ProcessName) && scanFile(process.Modules[0].FileName)) // If Search Protect Process and VirusTotal says it is not safe
                    fileDetected("Search Protect", process.Modules[0].FileName); // Report the file was detected
                if (pcHelper360Processes.Contains(process.ProcessName) && scanFile(process.Modules[0].FileName)) // If PC Helper 360 Process and VirusTotal says it is not safe
                    fileDetected("PC Helper 360", process.Modules[0].FileName); // Report the file was detected
            }
            endScan(); // Do menial ending tasks
        }

        private void specificScanButton_Click(object sender, EventArgs e) // Scan a specific file against VirusTotal's Database
        {
            if (openFileDialog.ShowDialog() == DialogResult.OK && openFileDialog.CheckFileExists) // If dialog was not cancelled and file exists
            {
                startScan(); // Do menial starting tasks

                console("Sending file to VirusTotal..."); // Tell console the file is being send to VirusTotal
                if (scanFile(openFileDialog.FileName)) // Scan file the user specified
                {
                    fileDetected("Potentially dangerous file", openFileDialog.FileName); // Report the file was detected
                }
                else
                {
                    MessageBox.Show("The file you specified seems to be safe.", "No danger detected", MessageBoxButtons.OK, MessageBoxIcon.Information); // Tell the user all seems safe
                }

                endScan(); // Do menial ending tasks
            }
        }

        private void startScan()
        {
            scannedItems.Clear(); // Clear scannedItems list
            consoleOutput.Text = ""; // Clear console
            console("Starting Scan..."); // Tell console the scan is starting
        }

        private void endScan()
        {
            console("Scan Complete!"); // Tell console the scan has ended
            colourConsole(); // Make the console look pretty
            MessageBox.Show("The system has finished it's scan...", "Scan Complete", MessageBoxButtons.OK, MessageBoxIcon.Information); // Alert to say scan has finished
        }

        private void fileDetected(String file, String fileName) // Report file was detected with alert and console output
        {
            console(file+" Detected @ "+fileName); // Tell console the file was found
                                                   //  MessageBox.Show(file+" Detected @ " + fileName, file+" Detected", MessageBoxButtons.OK, MessageBoxIcon.Warning); // Make an alert the file was found
            System.Console.WriteLine(file + " Detected @ " + fileName, file + " Detected");//, MessageBoxButtons.OK, MessageBoxIcon.Warning); // Make an alert the file was found
        }

        private bool scanFile(String fileName) // true - File is virus
        {
            MalwareReport rep1;
            bool test = false;
            List<string> infects = new List<string>();
            List<string> cleans = new List<string>();
            List<string> unrated = new List<string>();
            //string infected = "";
            //double clenct = 0.0;
            double unratedct = 0.0;
            int infectcount = 0;
            int totCount = 0;
            double infper = 0.0;
            double unrper = 0.0;
            if (scannedItems.ContainsKey(fileName)) return false; // Already scanned this file so just skip it...

            var data = string.Format("resource={0}&key={1}", GetMD5HashFromFile(fileName), apiKey); // MD5 and API Key to send
            var c = new WebClient(); // WebClient used for connection to API
            string s = c.UploadString(results, "POST", data); // Connect to the API and POST the data
            try
            {
                JObject o = JObject.Parse(s);
              //  viruses = "";
                foreach (JProperty jp in o["report"].Last)
                {
                    totCount++;
                    string value = jp.Value.ToString();
                    //viruses += jp.Name + ",";
                    if (value.Contains("clean"))
                    {
                        cleans.Add(jp.Name);
                    }
                    if (value.Contains("unrated"))
                    {
                        unrated.Add(jp.Name);
                        unratedct++;
                    }
                    else
                    {
                        infectcount++;
                        infects.Add(jp.Name);
                    }

                    

                   
                }
                infper = infectcount / totCount;
                unrper= unratedct / totCount;
                if (infper > 0.0)
                {
                    test = true;
                }


                rep1 = new MalwareReport(infects, cleans, unrated, infper, unrper);
            }
            catch(Exception ex)
            {
                
                return test;
            }
            scannedItems.Add(fileName,rep1);
            return test;
           
           // var r = ParseJSON(s); // Parse the response
            
  //          int nonBlank = 0; // If a line is blank, it is safe, numerous non-blanks = multiple virus confirmations
    //        foreach (string str in r.Values) // Cycle through response lines
      //      {
        //        if (Regex.Replace(str, @"\s+", "") != "") nonBlank++; // Count positive results (non-blank lines)
                //MessageBox.Show(str);
        //    }

         //   scannedItems.Add(fileName, nonBlank >= 20); // Say this item was scanned and store the result
      //      scannedItems.Add(fileName, nonBlank > 1); // Say this item was scanned and store the result
        //    return scannedItems[fileName]; // Return final scan result
        }

        private string httpPost(string uri, string parms)
        {
            WebRequest req = WebRequest.Create(uri);
            req.Credentials = new NetworkCredential(this.username, this.password);
            req.ContentType = "application/x-www-form-urlencoded";
            req.Method = "POST";
            byte[] bytes = System.Text.Encoding.ASCII.GetBytes(parms);
            Stream os = null;

            try
            {
                req.ContentLength = bytes.Length;
                os = req.GetRequestStream();
                System.Threading.Thread.Sleep(100);
                os.Write(bytes, 0, bytes.Length);
            }
            catch (WebException ex)
            {
            //    MessageBox.Show(ex.Message, "Request error");
            }
            finally
            {
                if (os != null)
                {
                    os.Close();
                }
            }

            try
            {
                WebResponse webResponse = req.GetResponse();
                if (webResponse == null)
                { return null; }
                StreamReader sr = new StreamReader(webResponse.GetResponseStream());
                return sr.ReadToEnd().Trim();
            }
            catch (WebException ex)
            {
                MessageBox.Show(ex.Message, "Response error");
            }
            return null;
        }

        public MalwareReport getURLScanReport(string nResource, bool autoScan)
        {
            MalwareReport rep;
            string r = string.Empty;
            List<string> clean = new List<string>();
            List<string> unrated = new List<string>();
            List<string> infected = new List<string>();
            double clenct = 0.0;
            double unratedct = 0.0;
            double infcount = 0.0;
            double tot = 0.0;
            Random random = new Random();
            int randomNumber = random.Next(10, 1000);

            if (autoScan)
            {
                r = this.httpPost("https://www.virustotal.com/api/get_url_report.json", "resource=" + nResource + "&key=" + this.apiKey + "&scan=1");
                System.Threading.Thread.Sleep(randomNumber);
            }
            else
            {
                r = this.httpPost("https://www.virustotal.com/api/get_url_report.json", "resource=" + nResource + "&key=" + this.apiKey + "&scan=0");
                System.Threading.Thread.Sleep(randomNumber);
            }

          //  again;
            JObject o = JObject.Parse(r);
            try
            {
                foreach (JProperty jp in o["report"].Last)
                {
                    tot++;
                    string value = jp.Value.ToString();
                    if (value.Contains("clean"))
                    {
                        clean.Add(jp.Name);
                        clenct++;
                    }
                    else if (value.Contains("unrated"))
                    {
                        unrated.Add(jp.Name);
                        unratedct++;
                    }
                    
                    else
                    {
                        infected.Add(jp.Name);
                        infcount++;
                    }
                    // this.results += jp.Name + "," + jp.First + "\n";

                }
            }
            catch(Exception ex)
            {
                r = this.httpPost("https://www.virustotal.com/api/get_url_report.json", "resource=" + nResource + "&key=" + this.apiKey + "&scan=0");
                System.Threading.Thread.Sleep(500);
                foreach (JProperty jp in o["report"].Last)
                {
                    tot++;
                    string value = jp.Value.ToString();
                    if (value.Contains("clean"))
                    {
                        clean.Add(jp.Name);
                        clenct++;
                    }
                    else if (value.Contains("unrated"))
                    {
                        unrated.Add(jp.Name);
                        unratedct++;
                    }
                    else
                    {
                        infected.Add(jp.Name);
                        infcount++;
                    }
                    // this.results += jp.Name + "," + jp.First + "\n";

                }
                System.Threading.Thread.Sleep(randomNumber);
            }

            double infPer = infcount / tot;
            double unrper = unratedct / tot;
            rep = new MalwareReport(infected, clean, unrated, infPer, unrper);
            return rep;
        }
        private bool scanLink(String fileName, bool auto) // true - File is virus
        {
            string viruses = "";
            bool test = false;
            if (scannedItems.ContainsKey(fileName)) return false; // Already scanned this file so just skip it...

            //    var data = string.Format("resource={0}&key={1}", GetMD5HashFromFile(fileName), apiKey); // MD5 and API Key to send
            //  var c = new WebClient(); // WebClient used for connection to API
            //  var data1 = fileName;
            //  string s = c.UploadString(results1, "POST", data1); // Connect to the API and POST the data
            MalwareReport rep;
            try
            {
                rep = getURLScanReport(fileName, auto);
                if (rep.getPerInf()>0.0) { test = true; }
            }
            catch (Exception ex)
            {

                return test;
            }
            scannedItems.Add(fileName, rep);
            return test;
           
        }
        private bool scanLink1(String fileName) // true - File is virus
        {
            string viruses = "";
            bool test = false;
            MalwareReport rep;
            string r = string.Empty;
            List<string> clean = new List<string>();
            List<string> infected = new List<string>();
            double clenct = 0.0;
            List<string> unrated = new List<string>();
            //string infected = "";
            //double clenct = 0.0;
            double unratedct = 0.0;
            double infcount = 0.0;
            double tot = 0.0;
            if (scannedItems.ContainsKey(fileName)) return false; // Already scanned this file so just skip it...

            var data = string.Format("resource={0}&key={1}", GetMD5HashFromFile(fileName), apiKey); // MD5 and API Key to send
            var c = new WebClient(); // WebClient used for connection to API
            var data1 = fileName;
            string s = c.UploadString(results1, "POST", data1); // Connect to the API and POST the data

            try
            {
                JObject o = JObject.Parse(s);
                viruses = "";
                foreach (JProperty jp in o["report"].Last)
                {
                    tot++;
                    string value = jp.Value.ToString();
                    if (value.Contains("clean"))
                    {
                        clean.Add(jp.Name);
                        clenct++;
                    }
                    else if (value.Contains("unrated"))
                    {
                        unrated.Add(jp.Name);
                        unratedct++;
                    }
                    else
                    {
                        infected.Add(jp.Name);
                        infcount++;
                    }
                    // this.results += jp.Name + "," + jp.First + "\n";

                }

                double infPer = infcount / tot;
                double unrper = unratedct / tot;
                rep = new MalwareReport(infected, clean, unrated, infPer, unrper);
            }
            catch (Exception ex)
            {

                return test;
            }
            scannedItems.Add(fileName, rep);
            return test;
            /* var r = ParseJSON(s); // Parse the response
             string tests = "";
             int nonBlank = 0; // If a line is blank, it is safe, numerous non-blanks = multiple virus confirmations
             foreach (string str in r.Values) // Cycle through response lines
             {
                 //  if (Regex.Replace(str, @"\s+", "") != "") nonBlank++; // Count positive results (non-blank lines)
                 //MessageBox.Show(str);
                 tests += r.Values;
             }

             //   scannedItems.Add(fileName, nonBlank >= 20); // Say this item was scanned and store the result
             scannedItems.Add(fileName, tests); // Say this item was scanned and store the result
             return scannedItems[fileName]; // Return final scan result */
        }

        private string GetMD5HashFromFile(string fileName) // Get MD5 of a file
        {
            using (var md5 = MD5.Create()) // Using MD5
            {
                try
                {
                    using (var stream = File.OpenRead(fileName)) // Open File
                    {
                        return BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", string.Empty).ToLower(); // Respond with MD5 of file, converted to lowercase
                    }
                }
                catch(Exception ex)
                {
                    swExceptions.WriteLine(fileName);
                    return null;
                }
            }
        }

        private Dictionary<string, string> ParseJSON(string json) // JSON Parser
        {
            var d = new Dictionary<string, string>(); // Line storage
            json = json.Replace("\"", null).Replace("[", null).Replace("]", null); // Replace wasted chars
            var r = json.Substring(1, json.Length - 2).Split(','); // Substring each value
            foreach (string s in r) // Cycle through results
            {
                d.Add(s.Split(':')[0], s.Split(':')[1]); // Add result to line storage
            }
            return d; // Return parsed JSON
        }

        private void console(String output) // Print to console with date/time and message
        {
            consoleOutput.Text += "[" + DateTime.Now.ToString("MM/dd/yy H:mm:ss") + "] " + output + Environment.NewLine;
        }

        private void colourConsole() // Colour the console
        {
         int lineCount = -1;
            foreach (var line in consoleOutput.Lines) // Cycle through all lines
            {
                // Make line red if not first or last (positive virus response)
                if (++lineCount == 0 || lineCount == consoleOutput.Lines.Length - 1) continue;
                consoleOutput.Select(consoleOutput.GetFirstCharIndexFromLine(lineCount), line.Length);
                consoleOutput.SelectionColor = Color.Red;
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            //string[] filePaths = Directory.GetFiles(@"c:\MyDir\");
            // ProcessDirectory("C");
            FolderBrowserDialog fbd = new FolderBrowserDialog();
            string dir;
       //     DialogResult result = fbd.ShowDialog();
            if (fbd.ShowDialog() == DialogResult.OK)
            {
             //   dir = .SelectedPath;
                dir = fbd.SelectedPath;
                ProcessDirectory(dir);
            }

            swMalewares.Close();
            swNormals.Close();
            swExceptions.Close();
            StreamWriter finalOutput = new StreamWriter("final.csv");
            finalOutput.WriteLine("link name" + "," + "viruses");
            foreach (KeyValuePair<string, MalwareReport> entry in scannedItems)
            {
                MalwareReport rep = entry.Value;

                finalOutput.WriteLine(entry.Key + "," + rep.getPerInf() );
                int k = 0;
                for(k=0; k<rep.getInf().Count();k++)
                {
                    finalOutput.Write("," + rep.getInf()[k]);
                }

                finalOutput.WriteLine();
            }

            finalOutput.Flush();
            finalOutput.Close();
            StreamWriter finalOutput1 = new StreamWriter("final1.csv");
            finalOutput1.WriteLine("link name" + "," + "unrated");
            foreach (KeyValuePair<string, MalwareReport> entry in scannedItems)
            {
                MalwareReport rep = entry.Value;
                finalOutput1.WriteLine(entry.Key + "," + rep.getPerUnr() );

                int k = 0;
                for (k = 0; k < rep.getunrated().Count(); k++)
                {
                    finalOutput.Write("," + rep.getunrated()[k]);
                }
                finalOutput.WriteLine();
            }
            finalOutput1.Flush();
            finalOutput1.Close();
            MessageBox.Show("Done");
        }
       
        StreamWriter swMalewares;// = new StreamWriter(malwares);
        StreamWriter swExceptions;// = new StreamWriter(exceptions);
        StreamWriter swNormals;// = new StreamWriter(normals);
        public void ProcessDirectory(string targetDirectory)
        {
            // Process the list of files found in the directory.
            string[] fileEntries = Directory.GetFiles(targetDirectory);
            tryAgain:
            foreach (string fileName in fileEntries)
            {
                System.Console.WriteLine("file tested.." + fileName);
                try {
                    if (scanFile(fileName)) // Scan file the user specified
                    {
                        fileDetected("Potentially dangerous file", fileName); // Report the file was detected
                        swMalewares.WriteLine(fileName);
                    }
                    else
                    {
                        System.Console.WriteLine(fileName + "... is OK");
                        swNormals.WriteLine(fileName);
                    }

             //   }
                }
            catch (Exception ex)
            {
                    System.Console.WriteLine(fileName + "Exception in call");

                    goto tryAgain;
            }
        }
            swExceptions.Flush();
            swMalewares.Flush();
            swNormals.Flush();
            // Recurse into subdirectories of this directory.
            string[] subdirectoryEntries = Directory.GetDirectories(targetDirectory);
            foreach (string subdirectory in subdirectoryEntries)
            {
                ProcessDirectory(subdirectory);
                swExceptions.Flush();
                swMalewares.Flush();
                swNormals.Flush();
            }
            
        }

        
        public void ProcessDirectory1(string targetFile)
        {
            List<string> lines = new List<string>();

            // 2
            // Use using StreamReader for disposing.
            using (StreamReader r = new StreamReader(targetFile))
            {
                // 3
                // Use while != null pattern for loop
                string line;
                while ((line = r.ReadLine()) != null)
                {
                    // 4
                    // Insert logic here.
                    // ...
                    // "line" is a line in the file. Add it to our List.
                    lines.Add(line);
                    extract(line);
                    try
                    {
                        foreach (LinkItem line1 in LinkFinder.Find(line))
                        {
                            extract(line1.Text);
                        }
                    }
                    catch(Exception ex)
                    {

                    }
                }      
            
            }
            swExceptions.Flush();
            swMalewares.Flush();
            swNormals.Flush();
            string final = "final_infected" + inputFilename + ".csv";
            string final1 = "final_unrated" + inputFilename + ".csv";
            StreamWriter finalOutput = new StreamWriter(final);
            finalOutput.WriteLine("link name" + "," + "Websites that decalre this link as malecious");
            foreach (KeyValuePair<string, MalwareReport> entry in scannedItems)
            {
              //  finalOutput.WriteLine(entry.Key + "," + entry.Value);

                MalwareReport rep = entry.Value;
                finalOutput.WriteLine(entry.Key + "," + rep.getPerInf());
                int k = 0;
                for(k=0; k< rep.getInf().Count; k++)
                {
                    finalOutput.Write("," + rep.getInf()[k]);
                }

                finalOutput.WriteLine();
            }
            StreamWriter finalOutput1 = new StreamWriter(final1);
            finalOutput.WriteLine("link name" + "," + "Websites that decalre this link as unrated");
            foreach (KeyValuePair<string, MalwareReport> entry in scannedItems)
            {
                //  finalOutput.WriteLine(entry.Key + "," + entry.Value);

                MalwareReport rep = entry.Value;
                finalOutput1.WriteLine(entry.Key  + "," + rep.getPerUnr());

                int k = 0;
                for (k = 0; k < rep.getunrated().Count; k++)
                {
                    finalOutput1.Write("," + rep.getunrated()[k]);
                }

                finalOutput1.WriteLine();
            }
            MessageBox.Show("Done");
            // Recurse into subdirectories of this directory.
            /*       string[] subdirectoryEntries = Directory.GetDirectories(targetDirectory);
                   foreach (string subdirectory in subdirectoryEntries)
                   {
                       ProcessDirectory(subdirectory);
                       swExceptions.Flush();
                       swMalewares.Flush();
                       swNormals.Flush();
                   }
                    */
        }

        private void extract(string line)
        {
            try
            {
                if (scanLink(line, true)) // Scan file the user specified
                {
                    fileDetected("Potentially dangerous file", line); // Report the file was detected
                    swMalewares.WriteLine(line);
                }
                else
                {
                    System.Console.WriteLine(line + "... is OK");
                    swNormals.WriteLine(line);
                }

                //   }
            }
            catch (Exception ex)
            {
                System.Console.WriteLine(line + "Exception in call");

             //   goto tryAgain;
            }
        }

       
        private void button2_Click(object sender, EventArgs e)
        {
            Stream myStream = null;
            OpenFileDialog openFileDialog1 = new OpenFileDialog();
            string result2 = "";
            openFileDialog1.InitialDirectory = "C:\\Users\\ialsmadi\\Desktop\\Malware\\SQL_Injection_Projects\\Main\\SQL_Injection-master\\SQL_Injection-master\\SQL注入\\bin\\Debug";
            openFileDialog1.Filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*";
            openFileDialog1.FilterIndex = 2;
            openFileDialog1.RestoreDirectory = true;
            
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                inputFilename = openFileDialog1.FileName;
                //    string path = @"C:\Users\ialsmadi\Desktop\Malware\";
                result2 = Path.GetFileNameWithoutExtension(inputFilename);
                string malwares = "maleware" + result2 + ".csv";
                string exceptions = "exceptions" + result2 + ".csv";
                string normals = "normals" + result2 + ".csv";
                swMalewares = new StreamWriter(malwares);
                swExceptions = new StreamWriter(exceptions);
                swNormals = new StreamWriter(normals);
                try
                {
                    if ((myStream = openFileDialog1.OpenFile()) != null)
                    {
                        ProcessDirectory1(openFileDialog1.FileName);
                    }

                }
                catch(Exception ex)
                {

                }
                }

            swMalewares.Close();
            swNormals.Close();
            swExceptions.Close();
            
            string final = "final" + result2 + ".csv";
            StreamWriter finalOutput = new StreamWriter(final);
            finalOutput.WriteLine("link name" + "," + "Websites that decalre this link as malecious");
            foreach (KeyValuePair<string, MalwareReport> entry in scannedItems)
            {
            //    finalOutput.WriteLine(entry.Key + "," + entry.Value);

                MalwareReport rep = entry.Value;
                finalOutput.WriteLine(entry.Key + "," + rep.getPerInf());
                int k = 0;
                for(k= 0; k< rep.getInf().Count;k++)
                {
                    finalOutput.Write("," + rep.getInf()[k]);
                }

                finalOutput.WriteLine();


            }
            finalOutput.Flush();
            finalOutput.Close();
            string final1 = "final_unrated" + result2 + ".csv";
            StreamWriter finalOutput1 = new StreamWriter(final1);
            finalOutput1.WriteLine("link name" + "," + "Websites that decalre this link as unrated");
            foreach (KeyValuePair<string, MalwareReport> entry in scannedItems)
            {
                //    finalOutput.WriteLine(entry.Key + "," + entry.Value);

                MalwareReport rep = entry.Value;
                finalOutput1.WriteLine(entry.Key + "," + rep.getPerUnr());
                int k = 0;
                for (k = 0; k < rep.getunrated().Count; k++)
                {
                    finalOutput1.Write("," + rep.getunrated()[k]);
                }

                finalOutput1.WriteLine();
            }
            finalOutput1.Flush();
            finalOutput1.Close();
            MessageBox.Show("Done");


        }
    }
}
