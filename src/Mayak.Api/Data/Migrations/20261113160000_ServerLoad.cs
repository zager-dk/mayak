using Mayak.Api.Data;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mayak.Api.Data.Migrations;

/// <summary>
/// Нагрузка серверов и трафик Xray в истории использования. Только новые столбцы со значением 0 по умолчанию;
/// существующие строки и таблицы не меняются.
/// </summary>
[DbContext(typeof(MayakDb))]
[Migration("20261113160000_ServerLoad")]
public sealed class ServerLoad : Migration
{
    static readonly string[] ServerLongs = ["XrayRxBytes", "XrayTxBytes", "MemUsedMax", "MemTotal", "NetRxBytes", "NetTxBytes", "DiskFree", "DiskTotal"];
    static readonly string[] ServerDoubles = ["CpuSum", "CpuMax", "Load1Max"];

    protected override void Up(MigrationBuilder m)
    {
        m.AddColumn<long>(name: "XrayRxBytes", table: "DeviceUsage", type: "bigint", nullable: false, defaultValue: 0L);
        m.AddColumn<long>(name: "XrayTxBytes", table: "DeviceUsage", type: "bigint", nullable: false, defaultValue: 0L);
        foreach (var c in ServerLongs) m.AddColumn<long>(name: c, table: "ServerUsage", type: "bigint", nullable: false, defaultValue: 0L);
        foreach (var c in ServerDoubles) m.AddColumn<double>(name: c, table: "ServerUsage", type: "double precision", nullable: false, defaultValue: 0.0);
        m.AddColumn<int>(name: "CpuSamples", table: "ServerUsage", type: "integer", nullable: false, defaultValue: 0);
    }

    protected override void Down(MigrationBuilder m)
    {
        m.DropColumn(name: "XrayRxBytes", table: "DeviceUsage");
        m.DropColumn(name: "XrayTxBytes", table: "DeviceUsage");
        foreach (var c in ServerLongs.Concat(ServerDoubles).Append("CpuSamples")) m.DropColumn(name: c, table: "ServerUsage");
    }
}
