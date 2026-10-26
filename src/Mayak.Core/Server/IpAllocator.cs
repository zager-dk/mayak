using System.Net;

namespace Mayak.Core.Server;

/// <summary>Выдача IPv4 в подсети VPN.</summary>
public static class IpAllocator
{
    public static uint ToUInt(string ip)
    {
        var b = IPAddress.Parse(ip).GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    public static string FromUInt(uint v) => $"{v >> 24}.{(v >> 16) & 255}.{(v >> 8) & 255}.{v & 255}";

    public static (uint Network, uint Broadcast) Range(string subnetAddress, int cidr)
    {
        uint mask = cidr == 0 ? 0 : uint.MaxValue << (32 - cidr);
        uint net = ToUInt(subnetAddress) & mask;
        return (net, net | ~mask);
    }

    /// <summary>
    /// Следующий адрес: максимальный занятый + 1 (как делает AmneziaVPN, чтобы её
    /// собственная выдача «последний + 1» не пересекалась с нашей). Если места в
    /// конце нет — первый свободный.
    /// </summary>
    public static string Next(string subnetAddress, int cidr, string serverAddress, IEnumerable<string> used)
    {
        var (net, broadcast) = Range(subnetAddress, cidr);
        var taken = new HashSet<uint>(used.Where(u => !string.IsNullOrWhiteSpace(u)).Select(ToUInt)) { net, broadcast, ToUInt(serverAddress) };

        uint max = taken.Where(t => t > net && t < broadcast).DefaultIfEmpty(net).Max();
        for (uint candidate = max + 1; candidate < broadcast; candidate++)
        {
            if ((candidate & 255) is 0 or 255) continue;
            if (!taken.Contains(candidate)) return FromUInt(candidate);
        }
        for (uint candidate = net + 1; candidate < broadcast; candidate++)
        {
            if ((candidate & 255) is 0 or 255) continue;
            if (!taken.Contains(candidate)) return FromUInt(candidate);
        }
        throw new MayakException("В подсети VPN закончились свободные адреса.");
    }

    /// <summary>Номер класса tc для устройства: смещение в подсети + 0x10, в hex.</summary>
    public static string TcClassId(string subnetAddress, int cidr, string ip)
    {
        var (net, _) = Range(subnetAddress, cidr);
        uint offset = ToUInt(ip) - net;
        return (offset + 0x10).ToString("x");
    }
}
