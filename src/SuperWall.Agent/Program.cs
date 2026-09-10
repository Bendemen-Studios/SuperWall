using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SuperWall.Agent;

public static class Program
{
    public static async Task Main(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddWindowsService(options => options.ServiceName = "SuperWall Agent");
        builder.Services.AddHostedService<PolicySyncService>();
        await builder.Build().RunAsync();
    }
}
