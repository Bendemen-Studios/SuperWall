using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SuperWall.Agent;

public static class Program
{
    public static async Task Main(string[] args)
    {
        if (args.Any(arg => arg.Equals("--uninstall", StringComparison.OrdinalIgnoreCase)))
        {
            Environment.ExitCode = SuperWallUninstaller.Run();
            return;
        }

        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddWindowsService(options => options.ServiceName = "SuperWallAgent");
        builder.Services.AddHostedService<PolicySyncService>();
        await builder.Build().RunAsync();
    }
}
