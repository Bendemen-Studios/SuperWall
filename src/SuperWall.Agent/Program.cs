using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Security.Principal;

namespace SuperWall.Agent;

public static class Program
{
    public static async Task Main(string[] args)
    {
        var command = args.FirstOrDefault()?.Trim().ToLowerInvariant();

        if (command is "-uninstall" or "--uninstall")
        {
            Environment.ExitCode = SuperWallUninstaller.Run();
            return;
        }

        if (command is "-version" or "--version")
        {
            if (!SuperWallUninstaller.IsAdministrator())
            {
                Environment.ExitCode = 740;
                return;
            }

            Console.WriteLine(typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "0.5.17");
            return;
        }

        if (command is "-status" or "--status")
        {
            if (!SuperWallUninstaller.IsAdministrator())
            {
                Environment.ExitCode = 740;
                return;
            }

            Environment.ExitCode = SuperWallUninstaller.PrintStatus();
            return;
        }

        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddWindowsService(options => options.ServiceName = "SuperWallAgent");
        builder.Services.AddHostedService<PolicySyncService>();
        await builder.Build().RunAsync();
    }
}
