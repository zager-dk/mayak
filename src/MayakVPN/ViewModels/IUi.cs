using Mayak.Core.Models;
using Mayak.Core.Server;
using MayakVPN.Services;

namespace MayakVPN.ViewModels;

public sealed record DeviceEditResult(string Name, DeviceKind Kind, int DownMbps, int UpMbps);

public sealed record UserEditResult(string Name, string Note);

public sealed record RelaySetup(ServerProfile Relay, bool IsNew, bool ManageViaRelay);

/// <summary>Диалоги, которые открывает главное окно по просьбе модели.</summary>
public interface IUi
{
    ServerProfile? EditServer(ServerProfile? existing, IEnumerable<ServerProfile> jumpCandidates);
    void ShowAddressCheck(string? host);
    void ShowPeople(ServerSnapshot? snap);
    IReadOnlyList<Person>? AskGrant(ServerSnapshot snap);
    InstallOptions? AskInstall(bool reinstall, string host);
    XrayInstallOptions? AskXrayInstall(bool reinstall, XrayEndpoint? current);
    RelaySetup? AskRelay(ServerProfile main, IEnumerable<ServerProfile> candidates);
    UserEditResult? EditUser(string title, VpnUser? existing);
    DeviceEditResult? EditDevice(string title, VpnDevice? existing, string userName, int defaultDown, int defaultUp);
    void ShowShare(ServerSnapshot snap, VpnUser user, VpnDevice device, string exportFolder);
    (VpnUser User, DeviceKind Kind)? AskAdopt(ForeignPeer peer, IReadOnlyList<VpnUser> users);
    bool Confirm(string text, string title, bool danger = false);
    void Error(string text);
    void Info(string text);
    string? PickFolder(string current);
}
