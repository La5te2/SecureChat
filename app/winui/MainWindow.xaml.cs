// Main WinUI window. This file handles user input, visual state, attachment
// preview policy, and event dispatch from the C++ native chat core.
using Microsoft.UI.Dispatching;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Microsoft.UI.Text;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.UI;
using WinRT.Interop;

namespace chat;

public sealed partial class MainWindow : Window
{
    private enum SessionMode
    {
        None,
        ConnectingHost,
        ConnectingJoin,
        PendingJoin,
        Host,
        Join
    }

    // 保存 native 回调委托的字段必须一直活着；如果只创建局部变量，
    // .NET GC 可能回收委托，C++ 再回调时就会崩溃或丢事件。
    private readonly NativeMethods.ChatEventCallback callback;
    private readonly DispatcherQueue dispatcherQueue;
    private readonly DispatcherTimer infoBarTimer = new();
    // WinUI 不直接维护真正的房间状态，真正状态在 C++ core 和 Server。
    // 这里保存的是界面需要显示和点击的成员快照。
    private readonly HashSet<string> participants = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> pendingParticipants = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> pendingJoinNamesByRequestId = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> pendingJoinRequestIdByParticipant = new(StringComparer.OrdinalIgnoreCase);
    // Blocked 是当前房间内的本机 UI 策略：右键成员卡片切换。
    // PKI 验证仍在 native 层完成；这里的颜色/预览策略不参与密钥认证。
    private readonly HashSet<string> blockedAttachmentMembers = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, VerifiedMemberInfo> verifiedAttachmentMembers = new(StringComparer.OrdinalIgnoreCase);
    // native core 先回调附件 metadata，再回调解密后的本地缓存路径。
    // 这里用队列把“来源成员”暂存起来，等真正渲染附件卡片时取出。
    private readonly Dictionary<string, Queue<AttachmentSenderInfo>> pendingAttachmentSenders = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Border> roomInstanceCards = new();
    private SessionMode sessionMode = SessionMode.None;
    private bool sidebarVisible = true;
    private bool resizingSidebar;
    private bool settingsHiding;
    private bool showOnlyMessages = true;
    private bool autoPreviewImages = true;
    private bool autoLoadAudio;
    private bool settingsReady;
    private bool refreshingLanguage;
    private bool infoBarFading;
    private string pendingLocalIdentityFingerprint = "";
    private string currentTheme = "Light";
    private string uiLanguage = "Chinese";
    private string roomName = "-";
    private Color bubbleColor = Color.FromArgb(255, 242, 242, 242);
    private Color bubbleTextColor = Color.FromArgb(255, 24, 24, 24);
    private Color metaTextColor = Color.FromArgb(255, 72, 72, 72);
    private double bubbleOpacity = 1;
    private double messageFontSize = 14;
    private double metaFontSize = 11;
    private FontFamily messageFontFamily = new("Segoe UI");
    private FontFamily metaFontFamily = new("Segoe UI");
    private ImageBrush? chatBackgroundBrush;
    private string? chatBackgroundPath;
    private bool isClosing;
    private int closeExitStarted;
    private LocalRoomInstanceInfo? selectedRoomInstance;
    private System.Threading.Tasks.TaskCompletionSource<LocalRoomInstanceInfo?>? roomInstanceSelectionSource;
    private string activeVoiceRecordingPath = "";
    private string relayStatusText = "-";
    private System.Threading.Tasks.Task? voiceStartTask;
    private bool voiceRecording;
    private bool voiceRecordingStopping;
    private bool suppressVoiceClick;
    private bool stopVoiceAfterStart;
    private bool sendVoiceAfterStart;
    private string voiceTargetAtRecordStart = "";

    private static readonly NativeMethods.ChatEventCallback NoOpCallback = (_, _, _) => { };
    // 附件预览状态只影响 WinUI 是否自动预览，不影响加解密和传输。
    // 加解密仍由 C++ secure relay 和 group key 完成。
    private enum AttachmentMemberState
    {
        Allowed,
        Pending,
        Blocked
    }
    private sealed record BubbleVisibilityState(bool IsMessageContent);
    private sealed record ChatDisplayLine(string Kind, string Sender, string Body, bool IsOwn, bool IsFilterable);
    private sealed record AttachmentSenderInfo(string DisplayName, string ActorId, string FileName = "")
    {
        public static readonly AttachmentSenderInfo Empty = new("", "", "");
    }
    private sealed record VerifiedMemberInfo(string DisplayName, string Fingerprint, string Subject);
    private sealed class LocalRoomInstanceInfo
    {
        public string roomDir { get; set; } = "";
        public string roomName { get; set; } = "";
        public string roomInstanceTokenDigest { get; set; } = "";
        public long modifiedTimeUnixMs { get; set; }
    }
    private sealed class MessageHistoryRecord
    {
        public long id { get; set; }
        public long createdAt { get; set; }
        public bool isOwn { get; set; }
        public string sender { get; set; } = "";
        public string actorId { get; set; } = "";
        public string kind { get; set; } = "message";
        public string body { get; set; } = "";
        public string messageJson { get; set; } = "";
    }
    private sealed class ForumHistoryRecord
    {
        public string boardMessageId { get; set; } = "";
        public string authorDisplayName { get; set; } = "";
        public string authorFingerprint { get; set; } = "";
        public string text { get; set; } = "";
        public long createdAtUnixMs { get; set; }
        public bool own { get; set; }
    }
    private const int InitialWindowWidth = 1180;
    private const int InitialWindowHeight = 760;
    // These caps only protect local WinUI preview/decoder paths. The protocol
    // transfer limit remains SECURECHAT_ATTACHMENT_MAX_BYTES in the native core.
    private const long MaxPreviewImageBytes = 15L * 1024 * 1024;
    private const long MaxPreviewAudioBytes = 50L * 1024 * 1024;
    private const int MaxPreviewImageDimension = 8192;
    private const long MaxPreviewImagePixels = 24_000_000;
    private const double MaxPreviewAudioSeconds = 600;
    private sealed record AttachmentPreviewInfo(
        string Kind,
        string Path,
        AttachmentSenderInfo Sender,
        long SizeBytes,
        bool IsOwnLocalAttachment,
        AttachmentMemberState MemberState);
    private sealed record ImagePreviewInfo(int Width, int Height);
    private sealed record WavPreviewInfo(int Channels, int SampleRate, int BitsPerSample, double DurationSeconds);

    public MainWindow()
    {
        InitializeComponent();
        dispatcherQueue = DispatcherQueue.GetForCurrentThread();
        SetWindowIcon();
        SetInitialWindowSize();
        Closed += MainWindow_Closed;
        infoBarTimer.Tick += async (_, _) =>
        {
            infoBarTimer.Stop();
            await FadeOutInfoBarAsync();
        };

        // C++ native.dll 只把事件字符串交给 C#；UI 更新必须切回 WinUI UI 线程。
        callback = OnNativeEvent;
        NativeMethods.chat_set_event_callback(callback, IntPtr.Zero);

        ApplyLanguage(false);
        ApplyAppTheme("Light");
        ApplyChatBackgroundSettings();
        UpdateBubbleStyleState();
        UpdateMessageTextStyleState();
        UpdateMetaTextStyleState();
        LoadAppConfig();
        settingsReady = true;
        ResetParticipants();
        SetSessionMode(SessionMode.None);
        RefreshRoomPanel();
        AddLine("status", "Ready");
    }

    private void OnNativeEvent(IntPtr kindPtr, IntPtr messagePtr, IntPtr userData)
    {
        if (isClosing) return;

        // native.dll 传来的 UTF-8 指针只在回调期间可靠，所以先复制成 C# string。
        var kind = Marshal.PtrToStringUTF8(kindPtr) ?? "status";
        var message = Marshal.PtrToStringUTF8(messagePtr) ?? "";
        // WinUI 控件只能在 UI 线程访问；DispatcherQueue 相当于把工作投递回主线程。
        dispatcherQueue.TryEnqueue(() =>
        {
            if (!isClosing) AddLine(kind, message);
        });
    }

    private void MainWindow_Closed(object sender, WindowEventArgs args)
    {
        if (Interlocked.Exchange(ref closeExitStarted, 1) != 0) return;
        isClosing = true;
        infoBarTimer.Stop();
        DisposeVoiceCaptureForExit();

        try
        {
            // 先把回调换成空实现，避免窗口销毁后 native core 继续向旧 UI 派发事件。
            NativeMethods.chat_set_event_callback(NoOpCallback, IntPtr.Zero);
        }
        catch
        {
        }

        System.Threading.Tasks.Task.Run(() =>
        {
            try
            {
                NativeMethods.chat_shutdown();
            }
            catch
            {
            }
            finally
            {
                TerminateCurrentProcess();
            }
        });

        // native shutdown 已经只发停止请求，不应长时间阻塞。
        // 这里保留很短的看门狗，防止底层库异常卡住时留下 WinUI 幽灵进程。
        System.Threading.Tasks.Task.Run(async () =>
        {
            await System.Threading.Tasks.Task.Delay(500).ConfigureAwait(false);
            TerminateCurrentProcess();
        });
    }

    private void DisposeVoiceCaptureForExit()
    {
        // 关闭窗口时直接关闭 WinMM 录音别名，避免麦克风句柄拖住退出。
        activeVoiceRecordingPath = "";
        voiceRecording = false;
        voiceRecordingStopping = false;
        voiceStartTask = null;
        try
        {
            CloseVoiceRecorder();
        }
        catch
        {
        }
    }

    private static void TerminateCurrentProcess()
    {
        try
        {
            if (OperatingSystem.IsWindows() && TerminateProcess(GetCurrentProcess(), 0))
            {
                return;
            }
            using var process = Process.GetCurrentProcess();
            process.Kill(entireProcessTree: true);
        }
        catch
        {
            Environment.FailFast("SecureChat could not terminate after window close.");
        }
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint exitCode);

    [DllImport("winmm.dll", CharSet = CharSet.Unicode)]
    private static extern int mciSendString(string command, StringBuilder? returnString, int returnLength, IntPtr hwndCallback);

    [DllImport("winmm.dll", CharSet = CharSet.Unicode)]
    private static extern bool mciGetErrorString(int errorCode, StringBuilder errorText, int errorTextSize);

    private bool TryReadSessionInputs(
        TextBox roomBox,
        TextBox userBox,
        out string room,
        out string user)
    {
        room = roomBox.Text.Trim();
        user = userBox.Text.Trim();
        if (room.Length == 0)
        {
            AddLine("error", "Room is required.");
            return false;
        }
        if (user.Length == 0)
        {
            AddLine("error", "User is required.");
            return false;
        }
        return true;
    }

    private bool ApplyRelayPoolEnvironment()
    {
        var configPath = AppConfigPath();
        if (!File.Exists(configPath))
        {
            AddLine("error", "Relay pool config is missing.");
            return false;
        }

        if (NativeMethods.chat_set_environment_variable("SECURECHAT_RELAY_POOL_FILE", configPath) == 0)
        {
            AddLine("error", "Failed to set relay pool config.");
            return false;
        }

        return true;
    }

    private async void HostJoin_Click(object sender, RoutedEventArgs e)
    {
        if (!TryReadSessionInputs(HostRoomBox, HostUserBox, out var room, out var user))
        {
            return;
        }
        if (!ApplyServerTlsEnvironment())
        {
            return;
        }

        var nickname = MemberDefaultNicknameBox.Text.Trim();
        var selected = await ShowRoomInstancePickerAsync(room, user, "host");
        if (selected is null) return;

        ClearAttachmentMemberStates();
        // 用户显式选择 room instance 后，WinUI 使用隐藏 room-dir 启动 Host。
        // 同名房间不会再由程序暗中选择“最新”的本地目录。
        var ok = NativeMethods.chat_host_start(
            selected.roomDir,
            user,
            nickname,
            MemberKeyPassBox.Password);
        if (ok != 0)
        {
            roomName = room;
            ResetParticipants();
            SetSessionMode(SessionMode.ConnectingHost);
        }
    }

    private void HostCreate_Click(object sender, RoutedEventArgs e)
    {
        if (!TryReadSessionInputs(HostRoomBox, HostUserBox, out var room, out var user))
        {
            return;
        }
        if (!ApplyServerTlsEnvironment())
        {
            return;
        }
        if (!ApplyRelayPoolEnvironment())
        {
            return;
        }

        var nickname = MemberDefaultNicknameBox.Text.Trim();
        ClearAttachmentMemberStates();
        // 创建房间时生成新的房间级 Root/Intermediate、Host 成员证书和 entrance.scp。
        // 监听、TLS/WSS 和 relay 都由外部 Server 进程处理。
        var ok = NativeMethods.chat_host_start_auto(
            room,
            user,
            nickname,
            MemberKeyPassBox.Password);
        if (ok != 0)
        {
            roomName = room;
            ResetParticipants();
            SetSessionMode(SessionMode.ConnectingHost);
        }
    }

    private async void JoinExisting_Click(object sender, RoutedEventArgs e)
    {
        if (!TryReadSessionInputs(JoinRoomBox, JoinUserBox, out var room, out var user))
        {
            return;
        }
        if (!ApplyServerTlsEnvironment())
        {
            return;
        }

        var nickname = MemberDefaultNicknameBox.Text.Trim();
        var selected = await ShowRoomInstancePickerAsync(room, user, "client");
        if (selected is null) return;

        ClearAttachmentMemberStates();
        // 加入房间只使用用户刚刚确认的本机 room-dir；
        // 首次拿到 entrance.scp 时应点“导入房间”。
        var ok = NativeMethods.chat_join_start(
            selected.roomDir,
            user,
            nickname,
            MemberKeyPassBox.Password);
        if (ok != 0)
        {
            roomName = room;
            ResetParticipants();
            AddPendingParticipant(user);
            SetSessionMode(SessionMode.ConnectingJoin);
        }
    }

    private async void JoinImport_Click(object sender, RoutedEventArgs e)
    {
        if (!TryReadSessionInputs(JoinRoomBox, JoinUserBox, out var room, out var user))
        {
            return;
        }

        var entranceFile = await PickEntranceFileAsync();
        if (string.IsNullOrWhiteSpace(entranceFile)) return;
        if (!ApplyServerTlsEnvironment())
        {
            return;
        }

        var nickname = MemberDefaultNicknameBox.Text.Trim();
        ClearAttachmentMemberStates();
        // 导入房间才打开 entrance.scp 文件选择器。
        // C# 只负责收集 UI 输入，
        // PKI、GKA、WebSocket 和 encrypted relay 都在 C++ core 中执行。
        var ok = NativeMethods.chat_join_start_auto(
            room,
            user,
            nickname,
            entranceFile,
            MemberKeyPassBox.Password);
        if (ok != 0)
        {
            roomName = room;
            ResetParticipants();
            AddPendingParticipant(user);
            SetSessionMode(SessionMode.ConnectingJoin);
        }
    }

    private void Exit_Click(object sender, RoutedEventArgs e)
    {
        ExitRoom();
    }

    private void Forum_Click(object sender, RoutedEventArgs e)
    {
        ForumOverlay.Opacity = 1;
        ForumOverlay.Visibility = Visibility.Visible;
        NativeMethods.chat_forum_sync();
        RefreshForumPanel();
    }

    private void ForumSync_Click(object sender, RoutedEventArgs e)
    {
        NativeMethods.chat_forum_sync();
        RefreshForumPanel();
    }

    private void ForumSend_Click(object sender, RoutedEventArgs e)
    {
        var text = ForumPostBox.Text.Trim();
        if (text.Length == 0) return;
        if (NativeMethods.chat_forum_post(text) != 0)
        {
            ForumPostBox.Text = "";
            RefreshForumPanel();
        }
    }

    private void ForumOverlay_PointerPressed(object sender, PointerRoutedEventArgs e)
    {
        ForumOverlay.Visibility = Visibility.Collapsed;
    }

    private void ForumPanel_PointerPressed(object sender, PointerRoutedEventArgs e)
    {
        e.Handled = true;
    }

    private void Send_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedSendMode() == "Voice")
        {
            if (suppressVoiceClick)
            {
                suppressVoiceClick = false;
                return;
            }
            AddLine("status", UiText("Hold the button to record voice.", "按住按钮录制语音。"));
            return;
        }

        SendSelectedMode();
    }

    private async void SendButton_PointerPressed(object sender, PointerRoutedEventArgs e)
    {
        if (SelectedSendMode() != "Voice" || !SendButton.IsEnabled) return;

        e.Handled = true;
        SendButton.CapturePointer(e.Pointer);
        suppressVoiceClick = true;
        stopVoiceAfterStart = false;
        sendVoiceAfterStart = false;
        voiceStartTask = StartVoiceRecordingAsync();
        await voiceStartTask;
        if (stopVoiceAfterStart)
        {
            await StopVoiceRecordingAsync(sendVoiceAfterStart);
        }
    }

    private async void SendButton_PointerReleased(object sender, PointerRoutedEventArgs e)
    {
        if (SelectedSendMode() != "Voice") return;

        e.Handled = true;
        SendButton.ReleasePointerCapture(e.Pointer);
        suppressVoiceClick = true;
        if (voiceStartTask is not null && !voiceStartTask.IsCompleted)
        {
            stopVoiceAfterStart = true;
            sendVoiceAfterStart = true;
            return;
        }
        await StopVoiceRecordingAsync(send: true);
    }

    private async void SendButton_PointerCanceled(object sender, PointerRoutedEventArgs e)
    {
        if (SelectedSendMode() != "Voice") return;

        e.Handled = true;
        SendButton.ReleasePointerCapture(e.Pointer);
        suppressVoiceClick = true;
        if (voiceStartTask is not null && !voiceStartTask.IsCompleted)
        {
            stopVoiceAfterStart = true;
            sendVoiceAfterStart = false;
            return;
        }
        await StopVoiceRecordingAsync(send: false);
    }

    private void SendModeBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (refreshingLanguage) return;
        UpdateSendButtonContent();
    }

    private void MessageBox_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == Windows.System.VirtualKey.Enter &&
            !Microsoft.UI.Input.InputKeyboardSource.GetKeyStateForCurrentThread(Windows.System.VirtualKey.Shift).HasFlag(Windows.UI.Core.CoreVirtualKeyStates.Down))
        {
            e.Handled = true;
            SendSelectedMode();
        }
    }

    private void SendSelectedMode()
    {
        // 发送按钮根据下拉框切换文本、图片、普通文件或语音。
        // 文件类消息先打开系统文件选择器，再把本地路径交给 native core 加密发送。
        var mode = SelectedSendMode();
        if (mode == "Image")
        {
            _ = SendPickedFileAsync(FileKind.Image);
            return;
        }
        if (mode == "File")
        {
            _ = SendPickedFileAsync(FileKind.File);
            return;
        }
        if (mode == "Voice")
        {
            AddLine("status", UiText("Hold the button to record voice.", "按住按钮录制语音。"));
            return;
        }

        SendCurrentMessage();
    }

    private void SendCurrentMessage()
    {
        // The target box is optional: empty means room broadcast. Non-empty
        // targets are resolved by current member display name only, avoiding
        // collisions with fixed protocol ids such as "host".
        var text = MessageBox.Text.Trim();
        if (text.Length == 0) return;
        var target = PrivateTargetBox.Text.Trim();

        if (text.Equals("/clear", StringComparison.OrdinalIgnoreCase))
        {
            MessagesPanel.Children.Clear();
            MessageBox.Text = "";
            return;
        }

        var ok = target.Length == 0
            ? NativeMethods.chat_send_line(text)
            : NativeMethods.chat_send_line_to(target, text);
        if (ok != 0)
        {
            MessageBox.Text = "";
        }
    }

    private enum FileKind
    {
        Image,
        File
    }

    private async System.Threading.Tasks.Task SendPickedFileAsync(FileKind kind)
    {
        // File picker paths stay local to this process. The native layer reads,
        // validates, encrypts, and chunks the file before sending.
        var file = await PickFileAsync(kind);
        if (file is null) return;
        var target = PrivateTargetBox.Text.Trim();

        // target 为空表示群发；target 非空时，native core 只按成员显示名解析并走私发 relay。
        _ = kind switch
        {
            FileKind.Image => target.Length == 0
                ? NativeMethods.chat_send_image(file.Path)
                : NativeMethods.chat_send_image_to(target, file.Path),
            FileKind.File => target.Length == 0
                ? NativeMethods.chat_send_file(file.Path)
                : NativeMethods.chat_send_file_to(target, file.Path),
            _ => 0
        };
    }

    private async System.Threading.Tasks.Task<Windows.Storage.StorageFile?> PickFileAsync(FileKind kind)
    {
        // UI filters mirror native validation. Native validation remains the
        // final security boundary if a path is supplied by another frontend.
        var picker = new FileOpenPicker();
        InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));
        switch (kind)
        {
            case FileKind.Image:
                picker.FileTypeFilter.Add(".jpg");
                picker.FileTypeFilter.Add(".jpeg");
                picker.FileTypeFilter.Add(".png");
                picker.FileTypeFilter.Add(".bmp");
                break;
            default:
                // File 是任意字节附件通道。接收端一律按有风险文件隔离处理，
                // 不在发送端文件选择器里限制扩展名。
                picker.FileTypeFilter.Add("*");
                break;
        }

        return await picker.PickSingleFileAsync();
    }

    private System.Threading.Tasks.Task StartVoiceRecordingAsync()
    {
        if (voiceRecording || voiceRecordingStopping || voiceStartTask is { IsCompleted: false })
        {
            return System.Threading.Tasks.Task.CompletedTask;
        }

        try
        {
            Directory.CreateDirectory(VoiceRecordingDirectory());
            var file = UniqueVoiceRecordingPath();

            CloseVoiceRecorder();
            SendMciCommand($"open new type waveaudio alias {VoiceRecorderAlias}");
            SendMciCommand($"record {VoiceRecorderAlias}");
            activeVoiceRecordingPath = file;
            voiceTargetAtRecordStart = PrivateTargetBox.Text.Trim();
            voiceRecording = true;
            SendButton.Content = UiText("Release", "松开");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException or IOException or COMException)
        {
            CloseVoiceRecorder();
            activeVoiceRecordingPath = "";
            voiceRecording = false;
            if (!isClosing)
            {
                UpdateSendButtonContent();
                AddLine("error", UiText("Voice recording failed: ", "语音录制失败：") + ex.Message);
            }
        }
        return System.Threading.Tasks.Task.CompletedTask;
    }

    private System.Threading.Tasks.Task StopVoiceRecordingAsync(bool send)
    {
        if ((!voiceRecording && string.IsNullOrWhiteSpace(activeVoiceRecordingPath)) || voiceRecordingStopping)
        {
            return System.Threading.Tasks.Task.CompletedTask;
        }

        voiceRecordingStopping = true;
        var path = activeVoiceRecordingPath;
        activeVoiceRecordingPath = "";
        voiceRecording = false;

        try
        {
            try
            {
                SendMciCommand($"stop {VoiceRecorderAlias}");
            }
            catch
            {
                // 录音设备在极短点击或权限变化时可能已经停止；继续尝试关闭别名。
            }
            if (send)
            {
                SendMciCommand($"save {VoiceRecorderAlias} \"{path}\"");
            }
            CloseVoiceRecorder();

            if (!send)
            {
                DeleteFileIfExists(path);
                return System.Threading.Tasks.Task.CompletedTask;
            }

            if (!File.Exists(path) || new FileInfo(path).Length <= 0)
            {
                DeleteFileIfExists(path);
                AddLine("error", UiText("Voice recording is empty.", "语音录制为空。"));
                return System.Threading.Tasks.Task.CompletedTask;
            }

            var target = voiceTargetAtRecordStart;
            var ok = target.Length == 0
                ? NativeMethods.chat_send_voice(path)
                : NativeMethods.chat_send_voice_to(target, path);
            if (ok == 0)
            {
                AddLine("error", UiText("Voice send failed.", "语音发送失败。"));
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or COMException or UnauthorizedAccessException)
        {
            CloseVoiceRecorder();
            DeleteFileIfExists(path);
            if (!isClosing)
            {
                AddLine("error", UiText("Voice recording failed: ", "语音录制失败：") + ex.Message);
            }
        }
        finally
        {
            voiceRecordingStopping = false;
            voiceTargetAtRecordStart = "";
            stopVoiceAfterStart = false;
            sendVoiceAfterStart = false;
            voiceStartTask = null;
            if (!isClosing)
            {
                UpdateSendButtonContent();
            }
        }
        return System.Threading.Tasks.Task.CompletedTask;
    }

    private static string VoiceRecordingDirectory()
    {
        return Path.Combine(AppContext.BaseDirectory, "logs", "voice-recordings");
    }

    private static string UniqueVoiceRecordingPath()
    {
        return Path.Combine(
            VoiceRecordingDirectory(),
            $"voice_{DateTimeOffset.Now:yyyyMMdd_HHmmss_fff}_{Guid.NewGuid():N}.wav");
    }

    private const string VoiceRecorderAlias = "securechat_voice";

    private static void SendMciCommand(string command)
    {
        var error = mciSendString(command, null, 0, IntPtr.Zero);
        if (error == 0) return;

        var text = new StringBuilder(256);
        var message = mciGetErrorString(error, text, text.Capacity)
            ? text.ToString()
            : "unknown multimedia error";
        throw new InvalidOperationException(message);
    }

    private static void CloseVoiceRecorder()
    {
        _ = mciSendString($"close {VoiceRecorderAlias}", null, 0, IntPtr.Zero);
    }

    private static void DeleteFileIfExists(string path)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path)) File.Delete(path);
        }
        catch
        {
        }
    }

    private void AddLine(string kind, string message)
    {
        if (isClosing) return;

        // Every native callback enters here. Status updates refresh room state;
        // attachment callbacks render media; encrypted chat JSON becomes bubbles.
        UpdateSessionStatus(kind, message);
        UpdateParticipants(kind, message);
        if (kind == "status" && message.StartsWith("Forum", StringComparison.OrdinalIgnoreCase))
        {
            RefreshForumPanel();
        }

        if (ShouldSuppressChatLine(kind, message)) return;
        if (TryRenderAttachment(kind, message)) return;

        var line = BuildDisplayLine(kind, message);
        if (line.Body.Length == 0) return;
        var content = new TextBlock
        {
            Text = line.Body,
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true,
            MaxWidth = 600,
            HorizontalAlignment = HorizontalAlignment.Left
        };
        RenderBubble(line.Kind, line.Sender, content, line.IsOwn, line.IsFilterable);
    }

    private static bool ShouldSuppressChatLine(string kind, string message)
    {
        if (string.Equals(kind, "relay_status", StringComparison.OrdinalIgnoreCase)) return true;
        if (string.Equals(kind, "log", StringComparison.OrdinalIgnoreCase)) return true;
        if (!string.Equals(kind, "status", StringComparison.OrdinalIgnoreCase)) return false;

        // GUI status is intentionally user-facing only. Endpoint details
        // stay in CLI/log paths so the chat area does not expose network internals.
        return message.StartsWith("client wss://", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("Clients can join with:", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("Attachment trust:", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("Forum sync", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("Forum records", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("Forum post", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("PKI identity ready:", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("PKI member verified:", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("GKA contribution verified:", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("Room members:", StringComparison.OrdinalIgnoreCase) ||
            message == "Waiting for room group key" ||
            message == "Room group key ready" ||
            message == "Signaling connected" ||
            message == "Signaling closed" ||
            message.Contains("endpoint", StringComparison.OrdinalIgnoreCase);
    }

    private bool TryRenderAttachment(string kind, string path)
    {
        // Attachments are decrypted and cached by the native core before this
        // callback. WinUI treats the cached file as untrusted UI input until
        // preview policy and lightweight structure checks allow rendering.
        if (kind is not ("image" or "voice" or "file"))
        {
            return false;
        }

        var sender = TakeAttachmentSender(kind);
        var sizeBytes = File.Exists(path) ? new FileInfo(path).Length : 0;
        var isOwnLocalAttachment = SenderOwnsAttachment(sender, path);
        // 这里的 path 已经是 native core 解密后的本地缓存文件。
        // UI 层仍然把它当作不可信文件，先计算来源和策略，再决定是否预览。
        var previewInfo = new AttachmentPreviewInfo(
            kind,
            path,
            sender,
            sizeBytes,
            isOwnLocalAttachment,
            AttachmentMemberStateForSender(sender));

        if (ShouldAutoPreviewAttachment(previewInfo) &&
            TryCreateAttachmentPreview(previewInfo, out var preview, out _))
        {
            RenderBubble(kind, SenderLabel(sender), preview, isOwnLocalAttachment, true);
            return true;
        }

        RenderBubble(kind, SenderLabel(sender), BuildAttachmentCard(previewInfo), isOwnLocalAttachment, true);
        return true;
    }

    private bool SenderOwnsAttachment(AttachmentSenderInfo sender, string path)
    {
        return string.IsNullOrWhiteSpace(SenderLabel(sender))
            ? IsOwnAttachmentPath(path)
            : IsOwnActor(sender.ActorId, sender.DisplayName);
    }

    private bool ShouldAutoPreviewAttachment(AttachmentPreviewInfo info)
    {
        // 普通文件永不自动打开，避免把未知格式交给系统关联程序。
        if (info.Kind == "file") return false;
        // 自己刚选择发送的本地文件可以按用户设置预览。
        if (info.IsOwnLocalAttachment) return info.Kind == "image" ? autoPreviewImages : autoLoadAudio;
        // 远端成员默认允许；用户右键成员卡片标记 Blocked 后不自动预览。
        if (info.MemberState == AttachmentMemberState.Blocked) return false;
        return info.Kind == "image" ? autoPreviewImages : autoLoadAudio;
    }

    private StackPanel BuildAttachmentCard(AttachmentPreviewInfo info)
    {
        var stack = new StackPanel
        {
            Spacing = 7,
            MinWidth = 260,
            MaxWidth = 560
        };
        stack.Children.Add(new TextBlock
        {
            Text = UiText("Attachment received", "附件已接收"),
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap
        });
        stack.Children.Add(new TextBlock
        {
            Text = $"{UiText("Type", "类型")}: {AttachmentKindLabel(info.Kind)}",
            TextWrapping = TextWrapping.Wrap
        });
        stack.Children.Add(new TextBlock
        {
            Text = $"{UiText("Source", "来源")}: {SenderLabel(info.Sender, UiText("Unavailable source", "来源未知"))}",
            TextWrapping = TextWrapping.Wrap
        });
        stack.Children.Add(new TextBlock
        {
            Text = $"{UiText("File", "文件")}: {AttachmentFileLabel(info)} ({FormatBytes(info.SizeBytes)})",
            TextWrapping = TextWrapping.Wrap
        });
        stack.Children.Add(new TextBlock
        {
            Text = AttachmentTrustLabel(info),
            Foreground = new SolidColorBrush(info.MemberState == AttachmentMemberState.Blocked
                ? Color.FromArgb(255, 176, 32, 32)
                : Color.FromArgb(255, 35, 112, 68)),
            TextWrapping = TextWrapping.Wrap
        });

        if (info.Kind is "image" or "voice")
        {
            var previewSlot = new StackPanel { Spacing = 7 };
            var previewButton = new Button
            {
                Content = UiText("Preview", "预览"),
                HorizontalAlignment = HorizontalAlignment.Left
            };
            ToolTipService.SetToolTip(previewButton, UiText(
                "Validate and preview this attachment locally.",
                "先做本地校验，再在界面中预览该附件。"));
            previewButton.Click += (_, _) =>
            {
                previewSlot.Children.Clear();
                if (TryCreateAttachmentPreview(info, out var preview, out var error))
                {
                    previewSlot.Children.Add(preview);
                    return;
                }

                previewSlot.Children.Add(new TextBlock
                {
                    Text = $"{UiText("Preview blocked", "预览已阻止")}: {error}",
                    Foreground = new SolidColorBrush(Color.FromArgb(255, 176, 32, 32)),
                    TextWrapping = TextWrapping.Wrap
                });
            };
            previewSlot.Children.Add(previewButton);
            stack.Children.Add(previewSlot);
        }

        return stack;
    }

    private bool TryCreateAttachmentPreview(AttachmentPreviewInfo info, out UIElement preview, out string error)
    {
        preview = new TextBlock { Text = UiText("No preview", "无预览") };
        error = "";
        try
        {
            if (info.Kind == "image")
            {
                // 图片预览前先解析尺寸和像素数，避免超大图片拖垮 UI 或解码器。
                ValidateImagePreview(info.Path, info.SizeBytes);
                preview = new Image
                {
                    Source = new BitmapImage(new Uri(info.Path)),
                    Stretch = Stretch.Uniform,
                    MaxWidth = 360,
                    MaxHeight = 260
                };
                return true;
            }

            if (info.Kind == "voice")
            {
                // 音频只支持受限 WAV 预览，先检查采样率、声道数、位深和时长。
                ValidateWavPreview(info.Path, info.SizeBytes);
                preview = new MediaPlayerElement
                {
                    Source = Windows.Media.Core.MediaSource.CreateFromUri(new Uri(info.Path)),
                    AreTransportControlsEnabled = true,
                    TransportControls = new MediaTransportControls
                    {
                        IsSeekBarVisible = true,
                        IsSeekEnabled = true
                    },
                    Width = 540,
                    Height = 110,
                    MinHeight = 110
                };
                return true;
            }

            error = UiText("Generic files are not previewed.", "普通文件不在界面中预览。");
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException)
        {
            error = ex.Message;
            return false;
        }
    }

    private void ValidateImagePreview(string path, long sizeBytes)
    {
        // 这些限制只保护 WinUI 预览路径；协议层附件大小限制在 C++ core 中。
        if (sizeBytes <= 0) throw new InvalidDataException("empty image file");
        if (sizeBytes > MaxPreviewImageBytes) throw new InvalidDataException("image is too large for inline preview");

        var image = ReadImagePreviewInfo(path);
        if (image.Width <= 0 || image.Height <= 0) throw new InvalidDataException("invalid image dimensions");
        if (image.Width > MaxPreviewImageDimension || image.Height > MaxPreviewImageDimension)
        {
            throw new InvalidDataException("image dimensions exceed preview limit");
        }
        if ((long)image.Width * image.Height > MaxPreviewImagePixels)
        {
            throw new InvalidDataException("image pixel count exceeds preview limit");
        }
    }

    private void ValidateWavPreview(string path, long sizeBytes)
    {
        // WAV 解析只读取文件头和 chunk 结构，不做杀毒或复杂格式隔离。
        if (sizeBytes <= 0) throw new InvalidDataException("empty audio file");
        if (sizeBytes > MaxPreviewAudioBytes) throw new InvalidDataException("audio is too large for inline preview");

        var wav = ReadWavPreviewInfo(path);
        if (wav.Channels is not (1 or 2)) throw new InvalidDataException("unsupported WAV channel count");
        if (wav.SampleRate < 8000 || wav.SampleRate > 192000) throw new InvalidDataException("unsupported WAV sample rate");
        if (wav.BitsPerSample is not (8 or 16 or 24 or 32)) throw new InvalidDataException("unsupported WAV bit depth");
        if (wav.DurationSeconds <= 0 || wav.DurationSeconds > MaxPreviewAudioSeconds)
        {
            throw new InvalidDataException("WAV duration exceeds preview limit");
        }
    }

    private void RememberAttachmentSender(string type, AttachmentSenderInfo sender)
    {
        if (string.IsNullOrWhiteSpace(sender.DisplayName) && string.IsNullOrWhiteSpace(sender.ActorId)) return;

        // metadata 回调和文件路径回调是分开的；按附件种类排队可保持顺序对应。
        var kind = type.ToLowerInvariant() switch
        {
            "image_meta" => "image",
            "voice_meta" => "voice",
            "file_meta" => "file",
            _ => ""
        };
        if (kind.Length == 0) return;

        if (!pendingAttachmentSenders.TryGetValue(kind, out var queue))
        {
            queue = new Queue<AttachmentSenderInfo>();
            pendingAttachmentSenders[kind] = queue;
        }
        queue.Enqueue(sender);
    }

    private AttachmentSenderInfo TakeAttachmentSender(string kind)
    {
        if (!pendingAttachmentSenders.TryGetValue(kind, out var queue) || queue.Count == 0)
        {
            return AttachmentSenderInfo.Empty;
        }
        return queue.Dequeue();
    }

    private bool IsOwnAttachmentPath(string path)
    {
        return !path.Contains("\\logs\\", StringComparison.OrdinalIgnoreCase) &&
            !path.Contains("/logs/", StringComparison.OrdinalIgnoreCase);
    }

    private AttachmentMemberState AttachmentMemberStateForSender(AttachmentSenderInfo sender)
    {
        // actorId 优先，displayName 兜底。默认允许预览；用户右键成员后才进入 Blocked。
        var keys = AttachmentTrustKeys(sender).ToList();
        if (keys.Any(key => blockedAttachmentMembers.Contains(key))) return AttachmentMemberState.Blocked;
        return AttachmentMemberState.Allowed;
    }

    private IEnumerable<string> AttachmentTrustKeys(AttachmentSenderInfo sender)
    {
        if (!string.IsNullOrWhiteSpace(sender.ActorId)) yield return sender.ActorId.Trim();
        if (!string.IsNullOrWhiteSpace(sender.DisplayName)) yield return sender.DisplayName.Trim();
    }

    private static string ParticipantTrustKey(string participant)
    {
        var parts = participant.Split(" / ", 2, StringSplitOptions.TrimEntries);
        return parts.Length == 2 && parts[1].Length > 0 ? parts[1] : participant.Trim();
    }

    private static IEnumerable<string> ParticipantTrustKeys(string participant)
    {
        var displayName = ParticipantDisplayName(participant);
        if (!string.IsNullOrWhiteSpace(displayName)) yield return displayName.Trim();

        var stableKey = ParticipantTrustKey(participant);
        if (!string.IsNullOrWhiteSpace(stableKey) &&
            !string.Equals(stableKey, displayName, StringComparison.OrdinalIgnoreCase))
        {
            yield return stableKey;
        }
    }

    private static string ParticipantLabel(string displayName, string memberId)
    {
        if (string.IsNullOrWhiteSpace(displayName)) return memberId.Trim();
        if (string.IsNullOrWhiteSpace(memberId) ||
            string.Equals(displayName.Trim(), memberId.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return displayName.Trim();
        }
        return $"{displayName.Trim()} / {memberId.Trim()}";
    }

    private static string ParticipantDisplayName(string participant)
    {
        return participant.Split(" / ", 2, StringSplitOptions.TrimEntries)[0];
    }

    private bool IsOwnParticipant(string participant)
    {
        return IsOwnSender(ParticipantDisplayName(participant));
    }

    private static string PrimaryParticipantKey(string participant)
    {
        return ParticipantTrustKey(participant);
    }

    private AttachmentMemberState MemberStateForParticipant(string participant)
    {
        if (IsPendingParticipant(participant)) return AttachmentMemberState.Pending;
        var keys = ParticipantTrustKeys(participant).ToList();
        if (keys.Any(key => blockedAttachmentMembers.Contains(key))) return AttachmentMemberState.Blocked;
        return AttachmentMemberState.Allowed;
    }

    private VerifiedMemberInfo? VerifiedInfoForParticipant(string participant)
    {
        foreach (var key in ParticipantTrustKeys(participant))
        {
            if (verifiedAttachmentMembers.TryGetValue(key, out var info)) return info;
        }
        return null;
    }

    private void ToggleBlockedParticipant(string participant)
    {
        if (IsPendingParticipant(participant))
        {
            RejectPendingParticipant(participant);
            return;
        }
        // Blocked 是当前房间内的临时 UI 状态：右键成员卡片切换红/绿。
        var key = PrimaryParticipantKey(participant);
        if (key.Length == 0) return;

        if (!blockedAttachmentMembers.Remove(key))
        {
            blockedAttachmentMembers.Add(key);
        }
        RefreshParticipants();
    }

    private void MarkVerifiedMember(string displayName, string memberId, string fingerprint, string subject = "")
    {
        // Verified 来自 C++ core 的 PKI 验证结果：证书链、签名和指纹已经通过 native 层检查。
        // WinUI 只保存显示名、成员 id 和指纹，用于成员列表颜色和复制指纹。
        var normalizedId = memberId.Trim();
        var normalizedName = displayName.Trim();
        var normalizedFingerprint = fingerprint.Trim();
        if (normalizedFingerprint.Length == 0) return;

        var shownName = normalizedName.Length == 0 ? normalizedId : normalizedName;
        var info = new VerifiedMemberInfo(shownName, normalizedFingerprint, subject.Trim());
        if (normalizedId.Length > 0) verifiedAttachmentMembers[normalizedId] = info;
        if (normalizedName.Length > 0) verifiedAttachmentMembers[normalizedName] = info;

        // Keep stable name plus id internally for PKI/fingerprint lookup, while
        // RefreshParticipants displays only the member name.
        pendingParticipants.Remove(normalizedName);
        pendingParticipants.Remove(normalizedId);
        RemoveParticipant(normalizedId);
        RemoveParticipant(normalizedName);
        var participant = ParticipantLabel(shownName, normalizedId);
        if (participant.Length > 0) participants.Add(participant);
        RefreshParticipants();
    }

    private bool TryMarkVerifiedMemberStatus(string message)
    {
        // native core 用 status 字符串把“成员 PKI 已验证”通知 UI。
        // 这里解析格式并转换成 WinUI 成员状态。
        const string prefix = "PKI member verified: ";
        if (!message.StartsWith(prefix, StringComparison.Ordinal)) return false;

        var parts = message[prefix.Length..]
            .Split(" / ", 4, StringSplitOptions.TrimEntries);
        if (parts.Length < 3) return false;

        MarkVerifiedMember(parts[0], parts[1], parts[2], parts.Length >= 4 ? parts[3] : "");
        return true;
    }

    private bool TryApplyAttachmentTrustStatus(string message)
    {
        // /trust 与 /untrust 由 C++ core 解析指纹前缀后回传到 UI。
        // WinUI 只更新本机附件预览策略，不把该状态持久化或发送给其他成员。
        const string prefix = "Attachment trust: ";
        if (!message.StartsWith(prefix, StringComparison.Ordinal)) return false;

        var parts = message[prefix.Length..]
            .Split(" / ", 4, StringSplitOptions.TrimEntries);
        if (parts.Length < 4) return false;

        var action = parts[0];
        var displayName = parts[1];
        var memberId = parts[2];
        var fingerprint = parts[3];
        if (!action.Equals("trust", StringComparison.OrdinalIgnoreCase) &&
            !action.Equals("untrust", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        MarkVerifiedMember(displayName, memberId, fingerprint);
        var key = PrimaryParticipantKey(ParticipantLabel(displayName, memberId));
        if (key.Length == 0) return true;

        if (action.Equals("untrust", StringComparison.OrdinalIgnoreCase))
        {
            blockedAttachmentMembers.Add(key);
        }
        else
        {
            blockedAttachmentMembers.Remove(key);
        }
        RefreshParticipants();
        return true;
    }

    private bool TryRememberLocalIdentityStatus(string message)
    {
        // 本地身份指纹可能先于 joined/room_members 事件到达，先暂存再补到自己的成员行。
        const string prefix = "PKI identity ready: ";
        if (!message.StartsWith(prefix, StringComparison.Ordinal)) return false;

        pendingLocalIdentityFingerprint = message[prefix.Length..].Trim();
        MarkLocalIdentityIfPossible();
        return true;
    }

    private bool TryMarkJoinedLocalMemberStatus(string message)
    {
        const string prefix = "Joined room ";
        if (!message.StartsWith(prefix, StringComparison.Ordinal)) return false;

        var open = message.LastIndexOf(" (", StringComparison.Ordinal);
        var close = message.EndsWith(")", StringComparison.Ordinal) ? message.Length - 1 : -1;
        var asIndex = message.LastIndexOf(" as ", StringComparison.Ordinal);
        if (asIndex < 0 || open <= asIndex || close <= open) return false;

        var username = message[(asIndex + 4)..open].Trim();
        var memberId = message[(open + 2)..close].Trim();
        if (username.Length > 0 && memberId.Length > 0 && pendingLocalIdentityFingerprint.Length > 0)
        {
            MarkVerifiedMember(username, memberId, pendingLocalIdentityFingerprint);
            return true;
        }
        return false;
    }

    private void MarkLocalIdentityIfPossible()
    {
        if (pendingLocalIdentityFingerprint.Length == 0) return;

        if (sessionMode == SessionMode.Host)
        {
            var displayName = HostUserBox.Text.Trim();
            MarkVerifiedMember(displayName.Length == 0 ? "host" : displayName, "host", pendingLocalIdentityFingerprint);
            return;
        }

        var ownParticipant = participants.FirstOrDefault(IsOwnParticipant);
        if (!string.IsNullOrWhiteSpace(ownParticipant))
        {
            var memberId = ParticipantTrustKey(ownParticipant);
            if (!string.IsNullOrWhiteSpace(memberId) &&
                !string.Equals(memberId, ParticipantDisplayName(ownParticipant), StringComparison.OrdinalIgnoreCase))
            {
                MarkVerifiedMember(ParticipantDisplayName(ownParticipant), memberId, pendingLocalIdentityFingerprint);
            }
        }
    }

    private void PruneAttachmentMemberStates()
    {
        // 房间成员变化后，清理已经离开的成员的 Blocked/Verified UI 状态。
        var liveKeys = participants.SelectMany(ParticipantTrustKeys)
            .Where(key => key.Length > 0)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        blockedAttachmentMembers.RemoveWhere(key => !liveKeys.Contains(key));
        foreach (var key in verifiedAttachmentMembers.Keys.Where(key => !liveKeys.Contains(key)).ToList())
        {
            verifiedAttachmentMembers.Remove(key);
        }
    }

    private static Color MemberStateBackground(AttachmentMemberState state)
    {
        return state switch
        {
            AttachmentMemberState.Blocked => Color.FromArgb(54, 176, 32, 32),
            AttachmentMemberState.Pending => Color.FromArgb(45, 120, 120, 120),
            AttachmentMemberState.Allowed => Color.FromArgb(54, 28, 135, 73),
            _ => Color.FromArgb(20, 0, 0, 0)
        };
    }

    private static Color MemberStateBorder(AttachmentMemberState state)
    {
        return state switch
        {
            AttachmentMemberState.Blocked => Color.FromArgb(190, 176, 32, 32),
            AttachmentMemberState.Pending => Color.FromArgb(140, 120, 120, 120),
            AttachmentMemberState.Allowed => Color.FromArgb(190, 28, 135, 73),
            _ => Color.FromArgb(50, 0, 0, 0)
        };
    }

    private bool IsPendingParticipant(string participant)
    {
        var normalized = participant.Trim();
        return pendingParticipants.Contains(normalized) ||
            ParticipantTrustKeys(participant).Any(key => pendingParticipants.Contains(key));
    }

    private void AddPendingParticipant(string name, string requestId = "")
    {
        var displayName = name.Trim();
        if (displayName.Length == 0) return;
        var normalizedRequestId = requestId.Trim();
        var participantKey = string.IsNullOrWhiteSpace(normalizedRequestId)
            ? displayName
            : ParticipantLabel(displayName, normalizedRequestId);
        pendingParticipants.Add(participantKey);
        participants.Add(participantKey);
        if (!string.IsNullOrWhiteSpace(requestId)) {
            pendingJoinNamesByRequestId[normalizedRequestId] = displayName;
            pendingJoinRequestIdByParticipant[participantKey] = normalizedRequestId;
        }
        RefreshParticipants();
    }

    private void RemovePendingParticipant(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return;
        var normalized = token.Trim();

        // pending 成员内部 key 是 "display / requestId"，界面只显示 display。
        // Host 可能收到 requestId、requestId 前缀、display 或 "display / id" 等不同状态文本，
        // 因此删除时同时匹配完整 key、显示名和 requestId。
        var keysToRemove = pendingParticipants
            .Where(participant => PendingParticipantMatches(participant, normalized))
            .ToList();

        if (pendingJoinNamesByRequestId.TryGetValue(normalized, out var name))
        {
            keysToRemove.AddRange(pendingParticipants
                .Where(participant => string.Equals(ParticipantDisplayName(participant), name, StringComparison.OrdinalIgnoreCase)));
        }

        foreach (var key in keysToRemove.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            pendingParticipants.Remove(key);
            participants.Remove(key);
            if (pendingJoinRequestIdByParticipant.TryGetValue(key, out var requestId))
            {
                pendingJoinNamesByRequestId.Remove(requestId);
            }
            pendingJoinRequestIdByParticipant.Remove(key);
        }
        pendingJoinNamesByRequestId.Remove(normalized);
        pendingJoinRequestIdByParticipant.Remove(normalized);
        RefreshParticipants();
    }

    private bool PendingParticipantMatches(string participant, string token)
    {
        if (string.IsNullOrWhiteSpace(participant) || string.IsNullOrWhiteSpace(token)) return false;
        var normalizedParticipant = participant.Trim();
        var normalizedToken = token.Trim();
        if (string.Equals(normalizedParticipant, normalizedToken, StringComparison.OrdinalIgnoreCase)) return true;

        var displayName = ParticipantDisplayName(normalizedParticipant);
        var tokenDisplayName = ParticipantDisplayName(normalizedToken);
        if (!string.IsNullOrWhiteSpace(displayName) &&
            string.Equals(displayName, normalizedToken, StringComparison.OrdinalIgnoreCase)) return true;
        if (!string.IsNullOrWhiteSpace(displayName) &&
            !string.IsNullOrWhiteSpace(tokenDisplayName) &&
            string.Equals(displayName, tokenDisplayName, StringComparison.OrdinalIgnoreCase)) return true;

        if (pendingJoinRequestIdByParticipant.TryGetValue(normalizedParticipant, out var requestId))
        {
            return string.Equals(requestId, normalizedToken, StringComparison.OrdinalIgnoreCase) ||
                requestId.StartsWith(normalizedToken, StringComparison.OrdinalIgnoreCase);
        }
        return false;
    }

    private string PendingRequestIdForParticipant(string participant)
    {
        var normalized = participant.Trim();
        if (pendingJoinRequestIdByParticipant.TryGetValue(normalized, out var requestId)) return requestId;
        foreach (var key in ParticipantTrustKeys(participant))
        {
            if (pendingJoinRequestIdByParticipant.TryGetValue(key, out requestId)) return requestId;
        }
        return "";
    }

    private void ApprovePendingParticipant(string participant)
    {
        if (sessionMode != SessionMode.Host) return;
        var requestId = PendingRequestIdForParticipant(participant);
        if (requestId.Length == 0) return;
        NativeMethods.chat_send_line("/approve " + requestId);
    }

    private void RejectPendingParticipant(string participant)
    {
        if (sessionMode != SessionMode.Host) return;
        var requestId = PendingRequestIdForParticipant(participant);
        if (requestId.Length == 0) return;
        NativeMethods.chat_send_line("/reject " + requestId);
    }

    private void CopyParticipantFingerprint(string participant)
    {
        // 成员列表点击复制证书指纹前 8 位；完整指纹只留在内部状态和 Host /list 中。
        var info = VerifiedInfoForParticipant(participant);
        if (info is null || string.IsNullOrWhiteSpace(info.Fingerprint))
        {
            ShowInfo(UiText("Fingerprint is not available", "指纹不可用"), InfoBarSeverity.Warning);
            return;
        }

        var prefix = info.Fingerprint.Length > 8 ? info.Fingerprint[..8] : info.Fingerprint;
        var package = new DataPackage();
        package.SetText(prefix);
        Clipboard.SetContent(package);
        ShowInfo(UiText("Fingerprint prefix copied", "指纹前缀已复制"), InfoBarSeverity.Success);
    }

    private static string SenderLabel(AttachmentSenderInfo sender, string fallback = "")
    {
        if (!string.IsNullOrWhiteSpace(sender.DisplayName)) return sender.DisplayName.Trim();
        if (!string.IsNullOrWhiteSpace(sender.ActorId)) return sender.ActorId.Trim();
        return fallback;
    }

    private string AttachmentTrustLabel(AttachmentPreviewInfo info)
    {
        if (info.IsOwnLocalAttachment) return UiText("Local file selected by you", "你本地选择的文件");
        return info.MemberState switch
        {
            AttachmentMemberState.Blocked => UiText("Blocked member: preview is disabled", "已阻止成员：禁用预览"),
            _ => UiText("Allowed member: auto-preview may run", "允许成员：可自动预览")
        };
    }

    private string AttachmentKindLabel(string kind)
    {
        return kind switch
        {
            "image" => UiText("Image", "图片"),
            "voice" => UiText("Audio", "音频"),
            "file" => UiText("File", "文件"),
            _ => kind
        };
    }

    private static string AttachmentFileLabel(AttachmentPreviewInfo info)
    {
        var fileName = string.IsNullOrWhiteSpace(info.Sender.FileName)
            ? Path.GetFileName(info.Path)
            : Path.GetFileName(info.Sender.FileName);
        return string.IsNullOrWhiteSpace(fileName) ? "attachment" : fileName;
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        var units = new[] { "KB", "MB", "GB" };
        var value = bytes / 1024.0;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return $"{value:0.##} {units[unit]}";
    }

    private static ImagePreviewInfo ReadImagePreviewInfo(string path)
    {
        // Read only container dimensions before constructing BitmapImage so a
        // huge or malformed file can be rejected before decoder allocation.
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length >= 24 &&
            bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47 &&
            bytes[12] == 0x49 && bytes[13] == 0x48 && bytes[14] == 0x44 && bytes[15] == 0x52)
        {
            return new ImagePreviewInfo((int)ReadUInt32BE(bytes, 16), (int)ReadUInt32BE(bytes, 20));
        }

        if (bytes.Length >= 26 && bytes[0] == 0x42 && bytes[1] == 0x4D)
        {
            var width = ReadInt32LE(bytes, 18);
            var height = Math.Abs(ReadInt32LE(bytes, 22));
            return new ImagePreviewInfo(width, height);
        }

        if (bytes.Length >= 4 && bytes[0] == 0xFF && bytes[1] == 0xD8)
        {
            return ReadJpegPreviewInfo(bytes);
        }

        throw new InvalidDataException("unsupported image header");
    }

    private static ImagePreviewInfo ReadJpegPreviewInfo(byte[] bytes)
    {
        var offset = 2;
        while (offset + 3 < bytes.Length)
        {
            while (offset < bytes.Length && bytes[offset] != 0xFF) offset++;
            while (offset < bytes.Length && bytes[offset] == 0xFF) offset++;
            if (offset >= bytes.Length) break;

            var marker = bytes[offset++];
            if (marker is 0xD9 or 0xDA) break;
            if (offset + 1 >= bytes.Length) break;

            var segmentLength = ReadUInt16BE(bytes, offset);
            offset += 2;
            if (segmentLength < 2 || offset + segmentLength - 2 > bytes.Length)
            {
                throw new InvalidDataException("invalid JPEG segment");
            }

            if (IsJpegStartOfFrame(marker))
            {
                if (segmentLength < 7) throw new InvalidDataException("invalid JPEG frame");
                var height = ReadUInt16BE(bytes, offset + 1);
                var width = ReadUInt16BE(bytes, offset + 3);
                return new ImagePreviewInfo(width, height);
            }

            offset += segmentLength - 2;
        }

        throw new InvalidDataException("JPEG dimensions not found");
    }

    private static bool IsJpegStartOfFrame(byte marker)
    {
        return marker is 0xC0 or 0xC1 or 0xC2 or 0xC3 or 0xC5 or 0xC6 or 0xC7 or
            0xC9 or 0xCA or 0xCB or 0xCD or 0xCE or 0xCF;
    }

    private static WavPreviewInfo ReadWavPreviewInfo(string path)
    {
        // Validate the RIFF/WAVE chunk layout before MediaPlayerElement sees the
        // file. This lowers accidental resource risk; it is not malware scanning.
        using var stream = File.OpenRead(path);
        using var reader = new BinaryReader(stream, Encoding.ASCII, leaveOpen: false);
        if (stream.Length < 44) throw new InvalidDataException("WAV file is too short");
        if (ReadFourCc(reader) != "RIFF") throw new InvalidDataException("missing RIFF header");
        _ = reader.ReadUInt32();
        if (ReadFourCc(reader) != "WAVE") throw new InvalidDataException("missing WAVE header");

        var hasFormat = false;
        var hasData = false;
        ushort audioFormat = 0;
        ushort channels = 0;
        var sampleRate = 0;
        uint byteRate = 0;
        ushort bitsPerSample = 0;
        uint dataBytes = 0;

        while (stream.Position + 8 <= stream.Length)
        {
            var chunkId = ReadFourCc(reader);
            var chunkSize = reader.ReadUInt32();
            var chunkStart = stream.Position;
            var chunkEnd = chunkStart + chunkSize;
            if (chunkEnd > stream.Length) throw new InvalidDataException("WAV chunk exceeds file size");

            if (chunkId == "fmt ")
            {
                if (chunkSize < 16) throw new InvalidDataException("invalid WAV fmt chunk");
                audioFormat = reader.ReadUInt16();
                channels = reader.ReadUInt16();
                sampleRate = (int)reader.ReadUInt32();
                byteRate = reader.ReadUInt32();
                _ = reader.ReadUInt16();
                bitsPerSample = reader.ReadUInt16();
                hasFormat = true;
            }
            else if (chunkId == "data")
            {
                dataBytes = chunkSize;
                hasData = true;
            }

            var nextChunk = chunkEnd + (chunkSize % 2);
            if (nextChunk > stream.Length) throw new InvalidDataException("invalid WAV chunk padding");
            stream.Position = nextChunk;
        }

        if (!hasFormat || !hasData) throw new InvalidDataException("WAV fmt/data chunk missing");
        if (audioFormat != 1) throw new InvalidDataException("only PCM WAV preview is allowed");
        if (byteRate == 0) throw new InvalidDataException("invalid WAV byte rate");
        return new WavPreviewInfo(channels, sampleRate, bitsPerSample, dataBytes / (double)byteRate);
    }

    private static string ReadFourCc(BinaryReader reader)
    {
        var bytes = reader.ReadBytes(4);
        if (bytes.Length != 4) throw new InvalidDataException("unexpected end of file");
        return Encoding.ASCII.GetString(bytes);
    }

    private static ushort ReadUInt16BE(byte[] bytes, int offset)
    {
        return (ushort)((bytes[offset] << 8) | bytes[offset + 1]);
    }

    private static uint ReadUInt32BE(byte[] bytes, int offset)
    {
        return ((uint)bytes[offset] << 24) |
            ((uint)bytes[offset + 1] << 16) |
            ((uint)bytes[offset + 2] << 8) |
            bytes[offset + 3];
    }

    private static int ReadInt32LE(byte[] bytes, int offset)
    {
        return bytes[offset] |
            (bytes[offset + 1] << 8) |
            (bytes[offset + 2] << 16) |
            (bytes[offset + 3] << 24);
    }

    private void RenderBubble(string kind, string sender, UIElement content, bool isOwnSender, bool isFilterable)
    {
        var alignment = isOwnSender ? HorizontalAlignment.Right : HorizontalAlignment.Left;
        var meta = string.IsNullOrWhiteSpace(sender)
            ? $"[{kind}]"
            : $"[{sender}][{kind}]";
        var group = new StackPanel
        {
            Spacing = 3,
            HorizontalAlignment = alignment,
            MaxWidth = 660
        };

        var metaText = new TextBlock
        {
            Text = meta,
            Tag = "MessageMeta",
            Opacity = 0.58,
            HorizontalAlignment = alignment,
            TextWrapping = TextWrapping.NoWrap,
            IsTextSelectionEnabled = true
        };

        var bubble = new Border
        {
            Tag = "MessageBubble",
            BorderBrush = new SolidColorBrush(Color.FromArgb(60, 0, 0, 0)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(10, 8, 10, 8),
            MaxWidth = 620,
            HorizontalAlignment = alignment,
            Child = content
        };
        ApplyMetaStyle(metaText);
        ApplyBubbleStyle(bubble);

        group.Children.Add(metaText);
        group.Children.Add(bubble);

        var row = new Grid
        {
            HorizontalAlignment = HorizontalAlignment.Stretch,
            Tag = new BubbleVisibilityState(isFilterable),
            Visibility = showOnlyMessages && !isFilterable
                ? Visibility.Collapsed
                : Visibility.Visible
        };
        row.Children.Add(group);
        MessagesPanel.Children.Add(row);

        MessagesScrollViewer.UpdateLayout();
        MessagesScrollViewer.ChangeView(null, MessagesScrollViewer.ScrollableHeight, null);
    }

    private void ReloadMessageHistory()
    {
        var rows = LoadMessageHistory();
        MessagesPanel.Children.Clear();
        foreach (var row in rows)
        {
            if (string.IsNullOrWhiteSpace(row.body)) continue;
            var content = new TextBlock
            {
                Text = row.body,
                TextWrapping = TextWrapping.Wrap,
                IsTextSelectionEnabled = true,
                MaxWidth = 600,
                HorizontalAlignment = HorizontalAlignment.Left
            };
            RenderBubble(
                string.IsNullOrWhiteSpace(row.kind) ? "message" : row.kind,
                row.sender,
                content,
                row.isOwn,
                true);
        }
    }

    private List<MessageHistoryRecord> LoadMessageHistory()
    {
        var required = NativeMethods.chat_get_message_history(IntPtr.Zero, 0);
        if (required <= 0) return new List<MessageHistoryRecord>();

        var buffer = Marshal.AllocHGlobal(required);
        try
        {
            var written = NativeMethods.chat_get_message_history(buffer, required);
            if (written < 0)
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
                required = -written;
                buffer = Marshal.AllocHGlobal(required);
                written = NativeMethods.chat_get_message_history(buffer, required);
            }
            if (written <= 1 || written > required) return new List<MessageHistoryRecord>();

            var bytes = new byte[written - 1];
            Marshal.Copy(buffer, bytes, 0, bytes.Length);
            var json = Encoding.UTF8.GetString(bytes);
            return JsonSerializer.Deserialize<List<MessageHistoryRecord>>(json) ?? new List<MessageHistoryRecord>();
        }
        catch (Exception ex)
        {
            AddLine("error", UiText("Failed to load local message history: ", "加载本地聊天记录失败：") + ex.Message);
            return new List<MessageHistoryRecord>();
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }
    }

    private void RefreshForumPanel()
    {
        if (ForumListPanel is null) return;
        var rows = LoadForumHistory();
        ForumListPanel.Children.Clear();
        if (rows.Count == 0)
        {
            ForumListPanel.Children.Add(new TextBlock
            {
                Text = UiText("No forum posts", "暂无留言"),
                TextWrapping = TextWrapping.Wrap,
                Foreground = new SolidColorBrush(metaTextColor)
            });
            return;
        }

        foreach (var row in rows)
        {
            var card = new Border
            {
                Padding = new Thickness(10),
                CornerRadius = new CornerRadius(8),
                Background = new SolidColorBrush(row.own
                    ? Color.FromArgb(255, 224, 239, 255)
                    : Color.FromArgb(255, 246, 246, 246))
            };
            var stack = new StackPanel { Spacing = 5 };
            stack.Children.Add(new TextBlock
            {
                Text = string.IsNullOrWhiteSpace(row.authorDisplayName) ? UiText("Unknown", "未知") : row.authorDisplayName,
                FontWeight = FontWeights.SemiBold,
                TextWrapping = TextWrapping.Wrap
            });
            stack.Children.Add(new TextBlock
            {
                Text = row.text,
                TextWrapping = TextWrapping.Wrap,
                IsTextSelectionEnabled = true
            });
            stack.Children.Add(new TextBlock
            {
                Text = FormatForumTime(row.createdAtUnixMs),
                FontSize = 11,
                Foreground = new SolidColorBrush(metaTextColor)
            });
            card.Child = stack;
            ForumListPanel.Children.Add(card);
        }
    }

    private List<ForumHistoryRecord> LoadForumHistory()
    {
        var required = NativeMethods.chat_get_forum_history(IntPtr.Zero, 0);
        if (required <= 0) return new List<ForumHistoryRecord>();

        var buffer = Marshal.AllocHGlobal(required);
        try
        {
            var written = NativeMethods.chat_get_forum_history(buffer, required);
            if (written < 0)
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
                required = -written;
                buffer = Marshal.AllocHGlobal(required);
                written = NativeMethods.chat_get_forum_history(buffer, required);
            }
            if (written <= 1 || written > required) return new List<ForumHistoryRecord>();

            var bytes = new byte[written - 1];
            Marshal.Copy(buffer, bytes, 0, bytes.Length);
            var json = Encoding.UTF8.GetString(bytes);
            return JsonSerializer.Deserialize<List<ForumHistoryRecord>>(json) ?? new List<ForumHistoryRecord>();
        }
        catch (Exception ex)
        {
            AddLine("error", UiText("Failed to load forum: ", "加载留言板失败：") + ex.Message);
            return new List<ForumHistoryRecord>();
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }
    }

    private static string FormatForumTime(long unixMs)
    {
        if (unixMs <= 0) return "";
        return DateTimeOffset.FromUnixTimeMilliseconds(unixMs).LocalDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.CurrentCulture);
    }

    private string SelectedSendMode()
    {
        return SendModeBox.SelectedItem is ComboBoxItem item
            ? item.Tag?.ToString() ?? "Text"
            : "Text";
    }

    private ChatDisplayLine BuildDisplayLine(string kind, string message)
    {
        var displayKind = string.IsNullOrWhiteSpace(kind) ? "status" : kind;
        var sender = "";
        var actorId = "";
        var body = message;
        if (displayKind == "message")
        {
            try
            {
                using var document = JsonDocument.Parse(message);
                var root = document.RootElement;
                var type = root.TryGetProperty("type", out var typeValue) ? typeValue.GetString() ?? "" : "";
                var from = root.TryGetProperty("from", out var fromValue) ? fromValue.GetString() ?? "" : "";
                actorId = from;
                if (root.TryGetProperty("payload", out var payload) &&
                    payload.ValueKind == JsonValueKind.Object)
                {
                    if (payload.TryGetProperty("actorId", out var actorIdValue))
                    {
                        actorId = actorIdValue.GetString() ?? actorId;
                    }
                    if (payload.TryGetProperty("displayName", out var displayName))
                    {
                        from = displayName.GetString() ?? from;
                    }
                }
                if (type == "member_identity")
                {
                    // Member identity announcements are encrypted control messages.
                    // Only Host-authored relay metadata is accepted as a PKI state update.
                    if (root.TryGetProperty("payload", out var identityPayload) &&
                        identityPayload.ValueKind == JsonValueKind.Object &&
                        identityPayload.TryGetProperty("relaySenderId", out var relaySenderId) &&
                        identityPayload.TryGetProperty("relaySenderKind", out var relaySenderKind) &&
                        string.Equals(relaySenderId.GetString(), "host", StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(relaySenderKind.GetString(), "host", StringComparison.OrdinalIgnoreCase))
                    {
                        var memberId = identityPayload.TryGetProperty("memberId", out var memberIdValue)
                            ? memberIdValue.GetString() ?? ""
                            : "";
                        var memberName = identityPayload.TryGetProperty("displayName", out var memberNameValue)
                            ? memberNameValue.GetString() ?? memberId
                            : memberId;
                        var fingerprint = identityPayload.TryGetProperty("fingerprint", out var fingerprintValue)
                            ? fingerprintValue.GetString() ?? ""
                            : "";
                        var subject = identityPayload.TryGetProperty("subject", out var subjectValue)
                            ? subjectValue.GetString() ?? ""
                            : "";
                        MarkVerifiedMember(memberName, memberId, fingerprint, subject);
                    }
                    body = "";
                    displayKind = "status";
                    return new ChatDisplayLine(displayKind, sender, body, false, false);
                }
                var privateTypeSuffix = root.TryGetProperty("payload", out var privatePayload) &&
                    privatePayload.ValueKind == JsonValueKind.Object &&
                    privatePayload.TryGetProperty("private", out var privateValue) &&
                    privateValue.ValueKind == JsonValueKind.True
                    ? " private"
                    : "";

                if (type == "text")
                {
                    body = root.TryGetProperty("content", out var content) ? content.GetString() ?? "" : "";
                    sender = from;
                    displayKind = "message" + privateTypeSuffix;
                }
                else if (type.EndsWith("_meta", StringComparison.OrdinalIgnoreCase))
                {
                    var name = root.TryGetProperty("name", out var nameValue) ? nameValue.GetString() ?? "" : "";
                    sender = from;
                    displayKind = "message" + privateTypeSuffix;
                    RememberAttachmentSender(type, new AttachmentSenderInfo(sender, actorId, name));
                    body = "";
                }
            }
            catch
            {
            }
        }

        return new ChatDisplayLine(
            displayKind,
            sender,
            body,
            IsOwnActor(actorId, sender),
            displayKind.StartsWith("message", StringComparison.OrdinalIgnoreCase));
    }

    private bool IsOwnActor(string actorId, string sender)
    {
        // Native messages carry both a display name and a stable actorId. Host
        // messages use actorId="host", so display-name-only checks would render
        // the Host's own messages on the left.
        if (!string.IsNullOrWhiteSpace(actorId))
        {
            var normalizedActorId = actorId.Trim();
            if (sessionMode == SessionMode.Host &&
                string.Equals(normalizedActorId, "host", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            var ownParticipant = participants.FirstOrDefault(IsOwnParticipant);
            if (!string.IsNullOrWhiteSpace(ownParticipant))
            {
                var ownParticipantId = ParticipantTrustKey(ownParticipant);
                if (string.Equals(normalizedActorId, ownParticipantId, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return IsOwnSender(sender);
    }

    private bool IsOwnSender(string sender)
    {
        var ownName = sessionMode switch
        {
            SessionMode.Host => HostUserBox.Text.Trim(),
            SessionMode.PendingJoin => JoinUserBox.Text.Trim(),
            SessionMode.Join => JoinUserBox.Text.Trim(),
            _ => ""
        };
        return ownName.Length > 0 && string.Equals(sender, ownName, StringComparison.OrdinalIgnoreCase);
    }

    private void SetSessionMode(SessionMode mode)
    {
        sessionMode = mode;
        var isConnected = mode is SessionMode.Host or SessionMode.Join;
        HostJoinButton.IsEnabled = mode == SessionMode.None;
        HostCreateButton.IsEnabled = mode == SessionMode.None;
        JoinExistingButton.IsEnabled = mode == SessionMode.None;
        JoinImportButton.IsEnabled = mode == SessionMode.None;
        // Exit is intentionally always available. Native chat_stop() is
        // idempotent, and keeping the button clickable lets the user recover
        // from connection errors where the UI mode is already None but a native
        // session is still closing.
        ExitButton.IsEnabled = true;
        MessageBox.IsEnabled = isConnected;
        SendModeBox.IsEnabled = isConnected;
        PrivateTargetBox.IsEnabled = isConnected;
        SendButton.IsEnabled = isConnected;
        if (mode == SessionMode.None)
        {
            roomName = "-";
        }
        RefreshRoomPanel();
    }

    private void ExitRoom()
    {
        NativeMethods.chat_stop();
        SetSessionMode(SessionMode.None);
        ResetParticipants();
    }

    private void UpdateSessionStatus(string kind, string message)
    {
        if (string.Equals(kind, "relay_status", StringComparison.OrdinalIgnoreCase))
        {
            relayStatusText = string.IsNullOrWhiteSpace(message) ? "-" : message.Trim();
            RefreshRoomPanel();
            return;
        }

        if (kind == "error")
        {
            ShowInfo(message, InfoBarSeverity.Error);
            return;
        }

        if (kind != "status") return;

        RefreshRoomPanel();

        if (message == "Session stopped" ||
            message == "Stopped" ||
            message == "Room is no longer available" ||
            message.StartsWith("Room is no longer available:", StringComparison.OrdinalIgnoreCase) ||
            message == "Signaling closed" ||
            message == "Signaling connection ended" ||
            message == "Signaling failed" ||
            message == "Host identity verification failed" ||
            message == "Username already in room")
        {
            SetSessionMode(SessionMode.None);
            ResetParticipants();
            ShowInfo(message, message == "Username already in room" ? InfoBarSeverity.Error : InfoBarSeverity.Warning);
            return;
        }

        if (message.StartsWith("Room created: ", StringComparison.OrdinalIgnoreCase))
        {
            SetSessionMode(SessionMode.Host);
            AddParticipant(HostUserBox.Text.Trim());
            MarkLocalIdentityIfPossible();
            ReloadMessageHistory();
            ShowInfo(message, InfoBarSeverity.Success);
            return;
        }

        if (message.StartsWith("Join request is waiting for Host approval", StringComparison.OrdinalIgnoreCase))
        {
            SetSessionMode(SessionMode.PendingJoin);
            AddPendingParticipant(JoinUserBox.Text.Trim());
            ShowInfo(UiText("Waiting for Host approval", "等待群主允许加入"), InfoBarSeverity.Informational);
            return;
        }

        if (message.StartsWith("Joined room", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("Rejoined room", StringComparison.OrdinalIgnoreCase))
        {
            SetSessionMode(SessionMode.Join);
            MarkLocalIdentityIfPossible();
            ReloadMessageHistory();
            NativeMethods.chat_forum_sync();
            RefreshForumPanel();
            ShowInfo(message, InfoBarSeverity.Success);
            return;
        }

        if (message.StartsWith("Host started", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("Clients can join", StringComparison.OrdinalIgnoreCase) ||
            message == "LAN room selected.")
        {
            ShowInfo(message, InfoBarSeverity.Success);
        }
    }

    private void ShowInfo(string message, InfoBarSeverity severity)
    {
        infoBarFading = false;
        ConnectionInfo.Opacity = 1;
        ConnectionInfo.Message = message;
        ConnectionInfo.Severity = severity;
        ConnectionInfo.IsOpen = true;
        infoBarTimer.Stop();
        infoBarTimer.Interval = TimeSpan.FromSeconds(InfoBarSecondsSlider?.Value ?? 5);
        infoBarTimer.Start();
    }

    private async System.Threading.Tasks.Task FadeOutInfoBarAsync()
    {
        if (infoBarFading || !ConnectionInfo.IsOpen) return;

        infoBarFading = true;
        for (var step = 9; step >= 0; step--)
        {
            if (!infoBarFading) return;
            ConnectionInfo.Opacity = step / 10.0;
            await System.Threading.Tasks.Task.Delay(28);
        }

        ConnectionInfo.IsOpen = false;
        ConnectionInfo.Opacity = 1;
        infoBarFading = false;
    }

    private void UpdateParticipants(string kind, string message)
    {
        // The native core currently emits room membership as a status string.
        // UI displays only names; stable ids stay internal for PKI/fingerprint lookup.
        if (kind != "status") return;

        TryRememberLocalIdentityStatus(message);
        TryMarkJoinedLocalMemberStatus(message);
        if (TryApplyAttachmentTrustStatus(message)) return;
        if (TryMarkVerifiedMemberStatus(message)) return;

        const string membersPrefix = "Room members: ";
        if (message.StartsWith(membersPrefix, StringComparison.Ordinal))
        {
            participants.Clear();
            foreach (var name in message[membersPrefix.Length..]
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                participants.Add(name);
            }
            foreach (var pending in pendingParticipants)
            {
                participants.Add(pending);
            }
            MarkLocalIdentityIfPossible();
            PruneAttachmentMemberStates();
            RefreshParticipants();
            return;
        }

        const string pendingPrefix = "Pending join verified: ";
        if (message.StartsWith(pendingPrefix, StringComparison.Ordinal))
        {
            var parts = message[pendingPrefix.Length..]
                .Split(" / ", 3, StringSplitOptions.TrimEntries);
            if (parts.Length >= 2)
            {
                AddPendingParticipant(parts[0], parts[1]);
            }
            return;
        }

        const string pendingCancelledPrefix = "Pending join cancelled: ";
        if (message.StartsWith(pendingCancelledPrefix, StringComparison.Ordinal))
        {
            RemovePendingParticipant(message[pendingCancelledPrefix.Length..].Trim());
            return;
        }

        const string pendingRejectedPrefix = "Pending join rejected: ";
        if (message.StartsWith(pendingRejectedPrefix, StringComparison.Ordinal))
        {
            RemovePendingParticipant(message[pendingRejectedPrefix.Length..].Trim());
            return;
        }

        const string pendingApprovedPrefix = "Pending join approved: ";
        if (message.StartsWith(pendingApprovedPrefix, StringComparison.Ordinal))
        {
            RemovePendingParticipant(message[pendingApprovedPrefix.Length..].Trim());
            return;
        }

        AddStatusName(message, "Client joined: ", removePending: true);
        AddStatusName(message, "Player joined: ", removePending: true);
        RemoveStatusName(message, "Client left: ");
        RemoveStatusName(message, "Player left: ");
    }

    private void AddStatusName(string message, string prefix, bool removePending = false)
    {
        if (!message.StartsWith(prefix, StringComparison.Ordinal)) return;
        var name = message[prefix.Length..].Trim();
        if (removePending) RemovePendingParticipant(name);
        AddParticipant(name);
    }

    private void RemoveStatusName(string message, string prefix)
    {
        if (!message.StartsWith(prefix, StringComparison.Ordinal)) return;
        RemoveParticipant(message[prefix.Length..].Trim());
        PruneAttachmentMemberStates();
        RefreshParticipants();
    }

    private void AddParticipant(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return;
        participants.Add(name.Trim());
        RefreshParticipants();
    }

    private void RemoveParticipant(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return;
        var normalized = name.Trim();
        participants.RemoveWhere(participant =>
            string.Equals(participant, normalized, StringComparison.OrdinalIgnoreCase) ||
            ParticipantTrustKeys(participant).Any(key => string.Equals(key, normalized, StringComparison.OrdinalIgnoreCase)));
    }

    private void ResetParticipants()
    {
        participants.Clear();
        pendingParticipants.Clear();
        pendingJoinNamesByRequestId.Clear();
        pendingJoinRequestIdByParticipant.Clear();
        ClearAttachmentMemberStates();
        RefreshParticipants();
    }

    private void ClearAttachmentMemberStates()
    {
        blockedAttachmentMembers.Clear();
        verifiedAttachmentMembers.Clear();
        pendingAttachmentSenders.Clear();
        pendingLocalIdentityFingerprint = "";
    }

    private void RefreshParticipants()
    {
        // Rebuilds the side rail from the normalized participant set. Keeping
        // this render-only avoids mixing UI controls with membership parsing.
        if (RoomParticipantsPanel is null) return;

        RoomParticipantsPanel.Children.Clear();
        var names = participants.ToList();
        if (names.Count == 0)
        {
            RoomParticipantsPanel.Children.Add(new TextBlock
            {
                Text = UiText("No participants", "暂无参与者"),
                Opacity = 0.7,
                TextWrapping = TextWrapping.Wrap
            });
            RefreshRoomPanel();
            return;
        }

        foreach (var name in names)
        {
            var state = MemberStateForParticipant(name);
            var verifiedInfo = VerifiedInfoForParticipant(name);
            var isPending = state == AttachmentMemberState.Pending;
            var row = new Grid { ColumnSpacing = 8 };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var identityBox = new Border
            {
                Padding = new Thickness(8, 5, 8, 5),
                Background = new SolidColorBrush(Color.FromArgb(0, 0, 0, 0)),
                Child = new TextBlock
                {
                    Text = ParticipantDisplayName(name),
                    TextWrapping = TextWrapping.Wrap,
                    FontWeight = FontWeights.SemiBold,
                    IsTextSelectionEnabled = false
                }
            };
            ToolTipService.SetToolTip(identityBox, isPending
                ? UiText("Click to approve; right-click to reject", "单击允许加入；右键拒绝加入")
                : verifiedInfo is null
                ? UiText("Right-click to block/unblock attachment preview", "右键阻止/解除阻止附件预览")
                : UiText("Click copies fingerprint prefix; right-click blocks/unblocks previews", "单击复制指纹前缀；右键阻止/解除阻止预览"));
            identityBox.Tapped += (_, args) =>
            {
                args.Handled = true;
                if (isPending) ApprovePendingParticipant(name);
                else CopyParticipantFingerprint(name);
            };
            row.Children.Add(identityBox);

            var participantCard = new Border
            {
                Padding = new Thickness(10, 7, 10, 7),
                Background = new SolidColorBrush(MemberStateBackground(state)),
                BorderBrush = new SolidColorBrush(MemberStateBorder(state)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Child = row
            };
            participantCard.Tapped += (_, args) =>
            {
                if (!isPending) return;
                args.Handled = true;
                ApprovePendingParticipant(name);
            };
            participantCard.RightTapped += (_, _) => ToggleBlockedParticipant(name);
            ToolTipService.SetToolTip(participantCard, isPending
                ? UiText("Click to approve; right-click to reject", "单击允许加入；右键拒绝加入")
                : state == AttachmentMemberState.Blocked
                ? UiText("Right-click to allow attachment previews", "右键恢复附件预览")
                : UiText("Right-click to block attachment previews", "右键阻止附件预览"));
            RoomParticipantsPanel.Children.Add(participantCard);
        }
        RefreshRoomPanel();
    }

    private void RefreshRoomPanel()
    {
        if (RoomModeText is null || RoomNameText is null) return;

        var mode = sessionMode switch
        {
            SessionMode.Host => UiText("client (host)", "客户端（群主）"),
            SessionMode.Join => UiText("client", "客户端"),
            SessionMode.PendingJoin => UiText("client pending", "客户端等待加入"),
            SessionMode.ConnectingHost => UiText("connecting client (host)", "正在连接客户端（群主）"),
            SessionMode.ConnectingJoin => UiText("connecting client", "正在连接客户端"),
            _ => UiText("not connected", "未连接")
        };
        RoomModeText.Text = $"{UiText("Mode", "模式")}: {mode}";
        RoomNameText.Text = $"{UiText("Room", "房间")}: {roomName}";
        if (RelayStatusText is not null)
        {
            RelayStatusText.Text = relayStatusText;
        }
    }

    private void ToggleSidebar_Click(object sender, RoutedEventArgs e)
    {
        sidebarVisible = !sidebarVisible;
        SidebarPanel.Visibility = sidebarVisible ? Visibility.Visible : Visibility.Collapsed;
        SidebarColumn.Width = sidebarVisible ? new GridLength(260) : new GridLength(0);
        SidebarResizeColumn.Width = sidebarVisible ? new GridLength(10) : new GridLength(0);
        SidebarResizeHandle.Visibility = sidebarVisible ? Visibility.Visible : Visibility.Collapsed;
        SidebarResizeIndicator.Opacity = 0;
    }

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        settingsHiding = false;
        SettingsOverlay.Opacity = 1;
        SettingsOverlay.Visibility = Visibility.Visible;
    }

    private async System.Threading.Tasks.Task HideSettingsAsync()
    {
        if (settingsHiding || SettingsOverlay.Visibility != Visibility.Visible) return;

        settingsHiding = true;
        for (var step = 9; step >= 0; step--)
        {
            SettingsOverlay.Opacity = step / 10.0;
            await System.Threading.Tasks.Task.Delay(14);
        }

        SettingsOverlay.Visibility = Visibility.Collapsed;
        SettingsOverlay.Opacity = 1;
        settingsHiding = false;
    }

    private async void SettingsOverlay_PointerPressed(object sender, PointerRoutedEventArgs e)
    {
        await HideSettingsAsync();
    }

    private void SettingsPanel_PointerPressed(object sender, PointerRoutedEventArgs e)
    {
        e.Handled = true;
    }

    private System.Threading.Tasks.Task<LocalRoomInstanceInfo?> ShowRoomInstancePickerAsync(
        string room,
        string user,
        string role)
    {
        var rooms = LoadLocalRoomInstances(room, user, role);
        if (rooms.Count == 0)
        {
            return System.Threading.Tasks.Task.FromResult<LocalRoomInstanceInfo?>(null);
        }

        roomInstanceSelectionSource?.TrySetResult(null);
        roomInstanceSelectionSource = new System.Threading.Tasks.TaskCompletionSource<LocalRoomInstanceInfo?>(
            System.Threading.Tasks.TaskCreationOptions.RunContinuationsAsynchronously);
        RenderRoomInstanceChoices(rooms);
        RoomInstanceOverlay.Opacity = 1;
        RoomInstanceOverlay.Visibility = Visibility.Visible;
        return roomInstanceSelectionSource.Task;
    }

    private List<LocalRoomInstanceInfo> LoadLocalRoomInstances(string room, string user, string role)
    {
        var required = NativeMethods.chat_list_local_room_dirs(room, user, role, IntPtr.Zero, 0);
        if (required <= 0) return new List<LocalRoomInstanceInfo>();

        var buffer = Marshal.AllocHGlobal(required);
        try
        {
            var written = NativeMethods.chat_list_local_room_dirs(room, user, role, buffer, required);
            if (written < 0)
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
                required = -written;
                buffer = Marshal.AllocHGlobal(required);
                written = NativeMethods.chat_list_local_room_dirs(room, user, role, buffer, required);
            }
            if (written <= 1 || written > required) return new List<LocalRoomInstanceInfo>();

            var bytes = new byte[written - 1];
            Marshal.Copy(buffer, bytes, 0, bytes.Length);
            var json = Encoding.UTF8.GetString(bytes);
            return JsonSerializer.Deserialize<List<LocalRoomInstanceInfo>>(json) ?? new List<LocalRoomInstanceInfo>();
        }
        catch (Exception ex)
        {
            AddLine("error", "Failed to read local room instances: " + ex.Message);
            return new List<LocalRoomInstanceInfo>();
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }
    }

    private void RenderRoomInstanceChoices(IReadOnlyList<LocalRoomInstanceInfo> rooms)
    {
        RoomInstanceListPanel.Children.Clear();
        roomInstanceCards.Clear();
        selectedRoomInstance = rooms[0];

        foreach (var room in rooms)
        {
            var card = new Border
            {
                Padding = new Thickness(10),
                CornerRadius = new CornerRadius(8),
                BorderThickness = new Thickness(2),
                BorderBrush = new SolidColorBrush(Color.FromArgb(0, 0, 0, 0)),
                Background = new SolidColorBrush(Color.FromArgb(0, 0, 0, 0)),
                Tag = room
            };
            card.PointerPressed += RoomInstanceCard_PointerPressed;

            var stack = new StackPanel { Spacing = 4 };
            stack.Children.Add(new TextBlock
            {
                Text = $"{UiText("Room", "房间名")}: {room.roomName}",
                TextWrapping = TextWrapping.Wrap
            });
            stack.Children.Add(new TextBlock
            {
                Text = $"{UiText("Created/imported time", "创建/导入时间")}: {FormatRoomInstanceTime(room.modifiedTimeUnixMs)}",
                TextWrapping = TextWrapping.Wrap
            });
            stack.Children.Add(new TextBlock
            {
                Text = $"Room instance: {ShortRoomInstanceDigest(room.roomInstanceTokenDigest)}",
                TextWrapping = TextWrapping.Wrap
            });

            card.Child = stack;
            roomInstanceCards.Add(card);
            RoomInstanceListPanel.Children.Add(card);
        }

        RefreshRoomInstanceCardSelection();
    }

    private void RoomInstanceCard_PointerPressed(object sender, PointerRoutedEventArgs e)
    {
        if (sender is Border { Tag: LocalRoomInstanceInfo room })
        {
            selectedRoomInstance = room;
            RefreshRoomInstanceCardSelection();
            e.Handled = true;
        }
    }

    private void RefreshRoomInstanceCardSelection()
    {
        var selectedBorder = new SolidColorBrush(Color.FromArgb(255, 0, 95, 184));
        var transparent = new SolidColorBrush(Color.FromArgb(0, 0, 0, 0));
        foreach (var card in roomInstanceCards)
        {
            var selected = card.Tag is LocalRoomInstanceInfo room &&
                selectedRoomInstance is not null &&
                string.Equals(room.roomDir, selectedRoomInstance.roomDir, StringComparison.OrdinalIgnoreCase);
            card.BorderBrush = selected ? selectedBorder : transparent;
        }
    }

    private void CompleteRoomInstanceSelection(LocalRoomInstanceInfo? room)
    {
        RoomInstanceOverlay.Visibility = Visibility.Collapsed;
        RoomInstanceOverlay.Opacity = 1;
        RoomInstanceListPanel.Children.Clear();
        roomInstanceCards.Clear();
        selectedRoomInstance = null;
        roomInstanceSelectionSource?.TrySetResult(room);
        roomInstanceSelectionSource = null;
    }

    private void RoomInstanceOverlay_PointerPressed(object sender, PointerRoutedEventArgs e)
    {
        CompleteRoomInstanceSelection(null);
    }

    private void RoomInstancePanel_PointerPressed(object sender, PointerRoutedEventArgs e)
    {
        e.Handled = true;
    }

    private void RoomInstanceConfirm_Click(object sender, RoutedEventArgs e)
    {
        if (selectedRoomInstance is null)
        {
            AddLine("error", UiText("Select a room instance first.", "请先选择一个房间实例。"));
            return;
        }
        CompleteRoomInstanceSelection(selectedRoomInstance);
    }

    private void RoomInstanceCancel_Click(object sender, RoutedEventArgs e)
    {
        CompleteRoomInstanceSelection(null);
    }

    private static string FormatRoomInstanceTime(long unixMs)
    {
        if (unixMs <= 0) return "-";
        return DateTimeOffset.FromUnixTimeMilliseconds(unixMs)
            .LocalDateTime
            .ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
    }

    private static string ShortRoomInstanceDigest(string digest)
    {
        var clean = new string((digest ?? "")
            .Where(Uri.IsHexDigit)
            .ToArray())
            .ToUpperInvariant();
        if (clean.Length == 0) return "-";
        return clean.Length <= 12 ? clean : clean[..12] + "...";
    }

    private void ThemeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (refreshingLanguage) return;
        ApplyAppTheme(ComboTag(ThemeComboBox));
        SaveAppConfigIfReady();
    }

    private void SkillLanguageComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (refreshingLanguage || !settingsReady) return;
        if (SkillLanguageComboBox is null) return;
        uiLanguage = ComboTag(SkillLanguageComboBox);
        ApplyLanguage();
        SaveAppConfigIfReady();
    }

    private void PersistedSetting_Changed(
        object sender,
        Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
    {
        SaveAppConfigIfReady();
    }

    private void PersistedSetting_Changed(object sender, TextChangedEventArgs e)
    {
        SaveAppConfigIfReady();
    }

    private void PersistedPassword_Changed(object sender, RoutedEventArgs e)
    {
        SaveAppConfigIfReady();
    }

    private void SettingsPanelOpacitySlider_ValueChanged(
        object sender,
        Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
    {
        if (SettingsPanel is null) return;
        SettingsPanel.Opacity = e.NewValue;
        SaveAppConfigIfReady();
    }

    private async void BrowseLocalServerTlsCa_Click(object sender, RoutedEventArgs e)
    {
        await PickPkiFileIntoAsync(LocalServerTlsCaBox);
    }

    private async System.Threading.Tasks.Task<string?> PickEntranceFileAsync()
    {
        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add(".scp");
        InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));

        var file = await picker.PickSingleFileAsync();
        return file?.Path;
    }

    private async System.Threading.Tasks.Task PickPkiFileIntoAsync(TextBox target)
    {
        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add(".pem");
        picker.FileTypeFilter.Add(".crt");
        picker.FileTypeFilter.Add(".cer");
        picker.FileTypeFilter.Add(".key");
        InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));

        var file = await picker.PickSingleFileAsync();
        if (file is null) return;

        target.Text = file.Path;
        SaveAppConfigIfReady();
    }

    private bool ApplyServerTlsEnvironment()
    {
        // SECURECHAT_LOCAL_TLS_CA 只影响本地/局域网 WSS 服务器证书验证。
        // 该项是可选项：公网证书通常由系统信任 CA 签发，本地/局域网自签证书才需要填写。
        return SetProcessEnvironmentFromBox("SECURECHAT_LOCAL_TLS_CA", LocalServerTlsCaBox);
    }

    private bool SetProcessEnvironmentFromBox(string name, TextBox textBox)
    {
        return SetProcessEnvironmentValue(name, textBox.Text.Trim());
    }

    private bool SetProcessEnvironmentValue(string name, string value)
    {
        var normalized = value.Trim();
        Environment.SetEnvironmentVariable(name, normalized.Length == 0 ? null : normalized);
        if (NativeMethods.chat_set_environment_variable(name, normalized) != 0) return true;

        AddLine("error", UiText("Failed to set native environment variable: ", "设置 native 环境变量失败：") + name);
        return false;
    }

    private async void ImportChatBackground_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add(".jpg");
        picker.FileTypeFilter.Add(".jpeg");
        picker.FileTypeFilter.Add(".png");
        picker.FileTypeFilter.Add(".bmp");
        InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));

        var file = await picker.PickSingleFileAsync();
        if (file is null) return;

        chatBackgroundBrush = new ImageBrush
        {
            ImageSource = new BitmapImage(new Uri(file.Path)),
            Stretch = Stretch.UniformToFill
        };
        chatBackgroundPath = file.Path;
        ChatBackgroundLayer.Background = chatBackgroundBrush;
        ApplyChatBackgroundSettings();
        SaveAppConfigIfReady();
    }

    private void ClearChatBackground_Click(object sender, RoutedEventArgs e)
    {
        chatBackgroundBrush = null;
        chatBackgroundPath = null;
        ChatBackgroundLayer.Background = null;
        ChatBackgroundLayer.Opacity = 0;
        ChatBackgroundWash.Opacity = 1;
        SaveAppConfigIfReady();
    }

    private void BackgroundOpacitySlider_ValueChanged(
        object sender,
        Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
    {
        ApplyChatBackgroundSettings();
        SaveAppConfigIfReady();
    }

    private void BackgroundCrop_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        ApplyChatBackgroundSettings();
        SaveAppConfigIfReady();
    }

    private void BubbleStyle_Changed(object sender, object e)
    {
        UpdateBubbleStyleState();
        UpdateMessageTextStyleState();
        RefreshMessageTextStyles();
        SaveAppConfigIfReady();
    }

    private void MessageTextStyle_Changed(object sender, object e)
    {
        UpdateMessageTextStyleState();
        RefreshMessageTextStyles();
        SaveAppConfigIfReady();
    }

    private void MetaTextStyle_Changed(object sender, object e)
    {
        UpdateMetaTextStyleState();
        RefreshMessageTextStyles();
        SaveAppConfigIfReady();
    }

    private void ShowOnlyMessagesToggleSwitch_Toggled(object sender, RoutedEventArgs e)
    {
        showOnlyMessages = ShowOnlyMessagesToggleSwitch.IsOn;
        RefreshBubbleVisibility();
        SaveAppConfigIfReady();
    }

    private void AttachmentPreviewSetting_Toggled(object sender, RoutedEventArgs e)
    {
        if (refreshingLanguage) return;
        if (AutoPreviewImagesToggleSwitch is null ||
            AutoLoadAudioToggleSwitch is null)
        {
            return;
        }

        autoPreviewImages = AutoPreviewImagesToggleSwitch.IsOn;
        autoLoadAudio = AutoLoadAudioToggleSwitch.IsOn;
        SaveAppConfigIfReady();
    }

    private void ApplyAppTheme(string theme)
    {
        currentTheme = theme;
        var isDark = theme is "Dark" or "Gothic";
        RootGrid.RequestedTheme = isDark ? ElementTheme.Dark : ElementTheme.Light;

        var root = theme == "Gothic" ? Color.FromArgb(255, 15, 11, 16) :
            isDark ? Color.FromArgb(255, 28, 28, 30) : Color.FromArgb(255, 250, 250, 250);
        var panel = theme == "Gothic" ? Color.FromArgb(255, 25, 18, 27) :
            isDark ? Color.FromArgb(255, 36, 36, 39) : Color.FromArgb(255, 248, 248, 248);
        var chat = theme == "Gothic" ? Color.FromArgb(255, 20, 15, 22) :
            isDark ? Color.FromArgb(255, 30, 31, 34) : Color.FromArgb(255, 255, 255, 255);
        var border = theme == "Gothic" ? Color.FromArgb(255, 110, 35, 50) :
            isDark ? Color.FromArgb(255, 74, 74, 78) : Color.FromArgb(255, 220, 220, 220);
        var foreground = isDark
            ? Color.FromArgb(255, 242, 242, 242)
            : Color.FromArgb(255, 28, 28, 28);

        RootGrid.Background = new SolidColorBrush(root);
        SidebarPanel.Background = new SolidColorBrush(panel);
        RightRailPanel.Background = new SolidColorBrush(panel);
        RightRailPanel.BorderBrush = new SolidColorBrush(border);
        ChatFrame.Background = new SolidColorBrush(chat);
        ChatFrame.BorderBrush = new SolidColorBrush(border);
        InputFrame.Background = new SolidColorBrush(panel);
        InputFrame.BorderBrush = new SolidColorBrush(border);
        SettingsPanel.Background = new SolidColorBrush(panel);
        SettingsPanel.BorderBrush = new SolidColorBrush(border);
        if (ForumPanel is not null)
        {
            ForumPanel.Background = new SolidColorBrush(panel);
            ForumPanel.BorderBrush = new SolidColorBrush(border);
        }
        // XAML 初始化时 ThemeComboBox 会先触发 SelectionChanged，
        // 此时后面声明的房间实例面板可能尚未创建。
        if (RoomInstancePanel is not null)
        {
            RoomInstancePanel.Background = new SolidColorBrush(panel);
            RoomInstancePanel.BorderBrush = new SolidColorBrush(border);
        }
        ChatBackgroundWash.Background = new SolidColorBrush(chat);
        SidebarToggleIcon.Source = new BitmapImage(new Uri(Path.Combine(
            AppContext.BaseDirectory,
            "Assets",
            isDark ? "sidebar_toggle_inverted.png" : "sidebar_toggle.png")));
        ExitIcon.Stroke = new SolidColorBrush(foreground);
        ForumIconOuter.Stroke = new SolidColorBrush(foreground);
        ForumIconInner.Stroke = new SolidColorBrush(foreground);
        SettingsIcon.Foreground = new SolidColorBrush(foreground);
        UpdateBubbleStyleState();
        UpdateMessageTextStyleState();
        UpdateMetaTextStyleState();
        ApplyChatBackgroundSettings();
        RefreshMessageTextStyles();
    }

    private void ApplyChatBackgroundSettings()
    {
        if (ChatBackgroundLayer is null ||
            BackgroundOpacitySlider is null ||
            BackgroundHorizontalComboBox is null ||
            BackgroundVerticalComboBox is null)
        {
            return;
        }

        if (chatBackgroundBrush is null)
        {
            ChatBackgroundWash.Opacity = 1;
            return;
        }

        ChatBackgroundLayer.Opacity = BackgroundOpacitySlider.Value;
        ChatBackgroundWash.Opacity = 1 - BackgroundOpacitySlider.Value;
        chatBackgroundBrush.AlignmentX = ComboTag(BackgroundHorizontalComboBox) switch
        {
            "Left" => AlignmentX.Left,
            "Right" => AlignmentX.Right,
            _ => AlignmentX.Center
        };
        chatBackgroundBrush.AlignmentY = ComboTag(BackgroundVerticalComboBox) switch
        {
            "Top" => AlignmentY.Top,
            "Bottom" => AlignmentY.Bottom,
            _ => AlignmentY.Center
        };
    }

    private void LoadChatBackgroundFromPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            chatBackgroundPath = null;
            chatBackgroundBrush = null;
            ChatBackgroundLayer.Background = null;
            ChatBackgroundLayer.Opacity = 0;
            ChatBackgroundWash.Opacity = 1;
            return;
        }

        chatBackgroundPath = path;
        chatBackgroundBrush = new ImageBrush
        {
            ImageSource = new BitmapImage(new Uri(path)),
            Stretch = Stretch.UniformToFill
        };
        ChatBackgroundLayer.Background = chatBackgroundBrush;
        ApplyChatBackgroundSettings();
    }

    private void UpdateBubbleStyleState()
    {
        if (BubbleColorComboBox is null || BubbleOpacitySlider is null) return;

        bubbleColor = ComboTag(BubbleColorComboBox) switch
        {
            "Parchment" => Color.FromArgb(255, 248, 238, 212),
            "PaleBlue" => Color.FromArgb(255, 225, 238, 248),
            "Crimson" => Color.FromArgb(255, 105, 37, 49),
            _ => currentTheme == "Gothic"
                ? Color.FromArgb(255, 45, 31, 39)
                : currentTheme == "Dark"
                    ? Color.FromArgb(255, 55, 56, 60)
                    : Color.FromArgb(255, 242, 242, 242)
        };
        bubbleOpacity = BubbleOpacitySlider.Value;
    }

    private void UpdateMessageTextStyleState()
    {
        if (MessageTextColorComboBox is null || MessageFontComboBox is null || MessageFontSizeSlider is null) return;

        bubbleTextColor = ComboTag(MessageTextColorComboBox) == "Auto"
            ? (IsDarkColor(bubbleColor) ? Color.FromArgb(255, 250, 248, 248) : Color.FromArgb(255, 24, 24, 24))
            : ColorChoice(ComboTag(MessageTextColorComboBox), Color.FromArgb(255, 24, 24, 24));
        messageFontFamily = FontChoice(ComboTag(MessageFontComboBox));
        messageFontSize = MessageFontSizeSlider.Value;
    }

    private void UpdateMetaTextStyleState()
    {
        if (MetaTextColorComboBox is null || MetaFontComboBox is null || MetaFontSizeSlider is null) return;

        metaTextColor = ComboTag(MetaTextColorComboBox) == "Auto"
            ? AutoMetaColor()
            : ColorChoice(ComboTag(MetaTextColorComboBox), AutoMetaColor());
        metaFontFamily = FontChoice(ComboTag(MetaFontComboBox));
        metaFontSize = MetaFontSizeSlider.Value;
    }

    private void RefreshMessageTextStyles()
    {
        if (MessagesPanel is null) return;

        foreach (var row in MessagesPanel.Children.OfType<Grid>())
        {
            foreach (var group in row.Children.OfType<StackPanel>())
            {
                foreach (var meta in group.Children.OfType<TextBlock>().Where(item => item.Tag as string == "MessageMeta"))
                {
                    ApplyMetaStyle(meta);
                }

                foreach (var bubble in group.Children.OfType<Border>().Where(item => item.Tag as string == "MessageBubble"))
                {
                    ApplyBubbleStyle(bubble);
                }
            }
        }
    }

    private void RefreshBubbleVisibility()
    {
        foreach (var row in MessagesPanel.Children.OfType<Grid>())
        {
            if (row.Tag is not BubbleVisibilityState state) continue;
            row.Visibility = showOnlyMessages && !state.IsMessageContent
                ? Visibility.Collapsed
                : Visibility.Visible;
        }
    }

    private void ApplyBubbleStyle(Border bubble)
    {
        bubble.Background = new SolidColorBrush(Color.FromArgb(
            (byte)Math.Round(255 * Math.Clamp(bubbleOpacity, 0, 1)),
            bubbleColor.R,
            bubbleColor.G,
            bubbleColor.B));
        if (bubble.Child is TextBlock text)
        {
            text.Foreground = new SolidColorBrush(bubbleTextColor);
            text.FontFamily = messageFontFamily;
            text.FontSize = messageFontSize;
        }
    }

    private void ApplyMetaStyle(TextBlock meta)
    {
        meta.Foreground = new SolidColorBrush(metaTextColor);
        meta.FontFamily = metaFontFamily;
        meta.FontSize = metaFontSize;
    }

    private Color AutoMetaColor()
    {
        return currentTheme switch
        {
            "Gothic" => Color.FromArgb(255, 220, 184, 190),
            "Dark" => Color.FromArgb(255, 196, 196, 196),
            _ => Color.FromArgb(255, 72, 72, 72)
        };
    }

    private static Color ColorChoice(string tag, Color fallback)
    {
        return tag switch
        {
            "Muted" => Color.FromArgb(255, 118, 118, 118),
            "Ink" => Color.FromArgb(255, 24, 24, 24),
            "White" => Color.FromArgb(255, 250, 250, 250),
            "Crimson" => Color.FromArgb(255, 148, 42, 58),
            "Gold" => Color.FromArgb(255, 174, 137, 66),
            _ => fallback
        };
    }

    private static FontFamily FontChoice(string tag)
    {
        return tag switch
        {
            "Serif" => new FontFamily("Georgia"),
            "Mono" => new FontFamily("Cascadia Mono"),
            _ => new FontFamily("Segoe UI")
        };
    }

    private static bool IsDarkColor(Color color)
    {
        var luminance = (0.2126 * color.R + 0.7152 * color.G + 0.0722 * color.B) / 255;
        return luminance < 0.45;
    }

    private static string ComboTag(ComboBox? comboBox)
    {
        if (comboBox is null) return "";
        if (comboBox.SelectedItem is ComboBoxItem item) return item.Tag?.ToString() ?? "";
        if (comboBox.SelectedIndex >= 0 &&
            comboBox.SelectedIndex < comboBox.Items.Count &&
            comboBox.Items[comboBox.SelectedIndex] is ComboBoxItem indexedItem)
        {
            return indexedItem.Tag?.ToString() ?? "";
        }
        return "";
    }

    private bool IsEnglishUi()
    {
        return string.Equals(uiLanguage, "English", StringComparison.OrdinalIgnoreCase);
    }

    private string UiText(string english, string chinese)
    {
        return IsEnglishUi() ? english : chinese;
    }

    private void ApplyLanguage(bool refreshMessages = true)
    {
        if (RootGrid is null) return;

        refreshingLanguage = true;
        var selectedSendMode = ComboTag(SendModeBox);
        var selectedTheme = ComboTag(ThemeComboBox);
        var selectedLanguage = ComboTag(SkillLanguageComboBox);
        var selectedBackgroundX = ComboTag(BackgroundHorizontalComboBox);
        var selectedBackgroundY = ComboTag(BackgroundVerticalComboBox);
        var selectedBubbleColor = ComboTag(BubbleColorComboBox);
        var selectedMessageTextColor = ComboTag(MessageTextColorComboBox);
        var selectedMessageFont = ComboTag(MessageFontComboBox);
        var selectedMetaTextColor = ComboTag(MetaTextColorComboBox);
        var selectedMetaFont = ComboTag(MetaFontComboBox);

        try
        {
            HostPivotItem.Header = UiText("Host", "主持");
            JoinPivotItem.Header = UiText("Join", "加入");
            RoomPivotItem.Header = UiText("Room", "房间");
            HostRoomBox.Header = UiText("Room", "房间");
            HostUserBox.Header = UiText("User", "用户");
            HostJoinButton.Content = UiText("Join Room", "加入房间");
            HostCreateButton.Content = UiText("Create Room", "创建房间");
            JoinRoomBox.Header = UiText("Room", "房间");
            JoinUserBox.Header = UiText("User", "用户");
            JoinExistingButton.Content = UiText("Join Room", "加入房间");
            JoinImportButton.Content = UiText("Import Room", "导入房间");
            ToolTipService.SetToolTip(ExitButton, UiText("Exit room", "离开房间"));
            ToolTipService.SetToolTip(ForumButton, UiText("Forum", "留言板"));
            ForumTitleText.Text = UiText("Forum", "留言板");
            ForumSyncButton.Content = UiText("Sync", "同步");
            ForumPostBox.PlaceholderText = UiText("Forum message", "输入留言");
            ForumSendButton.Content = UiText("Send", "发送");
            RoomStatusHeaderText.Text = UiText("Room Status", "房间状态");
            RelayStatusHeaderText.Text = UiText("Relay status", "中继器状态");
            RoomParticipantsHeaderText.Text = UiText("Participants", "参与者");

            MessageBox.PlaceholderText = UiText("Type a message", "输入消息");
            PrivateTargetBox.PlaceholderText = UiText("To: Member", "私信对象");
            SetComboItemContent(SendModeBox, "Text", UiText("Texts", "文字"));
            SetComboItemContent(SendModeBox, "Image", UiText("Image", "图片"));
            SetComboItemContent(SendModeBox, "File", UiText("Files", "文件"));
            SetComboItemContent(SendModeBox, "Voice", UiText("Voice", "语音"));

            StyleHeaderText.Text = UiText("Style", "样式");
            ThemeComboBox.Header = UiText("Theme", "主题");
            SetComboItemContent(ThemeComboBox, "Light", UiText("Light", "浅色"));
            SetComboItemContent(ThemeComboBox, "Dark", UiText("Dark", "深色"));
            SetComboItemContent(ThemeComboBox, "Gothic", UiText("Gothic", "哥特"));
            SkillLanguageComboBox.Header = UiText("Language", "语言");
            SetComboItemContent(SkillLanguageComboBox, "Chinese", IsEnglishUi() ? "Chinese" : "中文");
            SetComboItemContent(SkillLanguageComboBox, "English", "English");
            InfoBarSecondsSlider.Header = UiText("InfoBar seconds", "提示停留秒数");
            SettingsPanelOpacitySlider.Header = UiText("Settings panel opacity", "设置面板透明度");
            ShowOnlyMessagesToggleSwitch.Header = UiText("Only messages", "只看消息");
            ShowOnlyMessagesToggleSwitch.OnContent = UiText("On", "开");
            ShowOnlyMessagesToggleSwitch.OffContent = UiText("Off", "关");
            AttachmentSafetyHeaderText.Text = UiText("Attachment Safety", "附件安全");
            AutoPreviewImagesToggleSwitch.Header = UiText("Auto preview images", "自动预览图片");
            AutoPreviewImagesToggleSwitch.OnContent = UiText("On", "开");
            AutoPreviewImagesToggleSwitch.OffContent = UiText("Off", "关");
            AutoLoadAudioToggleSwitch.Header = UiText("Auto load audio", "自动加载音频");
            AutoLoadAudioToggleSwitch.OnContent = UiText("On", "开");
            AutoLoadAudioToggleSwitch.OffContent = UiText("Off", "关");
            RoomIdentityHeaderText.Text = UiText("Room Identity", "房间身份");
            MemberDefaultNicknameBox.Header = UiText("Member default nickname", "成员默认昵称");
            MemberKeyPassBox.Header = UiText("Member key passphrase", "成员私钥口令");
            ServerTlsHeaderText.Text = UiText("Server TLS", "服务器 TLS");
            LocalServerTlsCaBox.Header = UiText("Local Server TLS CA", "本地服务器 TLS 信任根");
            BrowseLocalServerTlsCaButton.Content = UiText("Browse", "选择");
            RoomInstanceTitleText.Text = UiText("Select Room Instance", "选择房间实例");
            RoomInstanceConfirmButton.Content = UiText("Confirm", "确认");
            RoomInstanceCancelButton.Content = UiText("Cancel", "取消");
            ChatBackgroundHeaderText.Text = UiText("Chat Background", "聊天背景");
            ImportChatBackgroundButton.Content = UiText("Import Image", "导入图片");
            ClearChatBackgroundButton.Content = UiText("Clear Image", "清除图片");
            BackgroundOpacitySlider.Header = UiText("Image opacity", "图片透明度");
            BackgroundHorizontalComboBox.Header = UiText("Crop X", "横向裁切");
            BackgroundVerticalComboBox.Header = UiText("Crop Y", "纵向裁切");
            SetComboItemContent(BackgroundHorizontalComboBox, "Left", UiText("Left", "左"));
            SetComboItemContent(BackgroundHorizontalComboBox, "Center", UiText("Center", "居中"));
            SetComboItemContent(BackgroundHorizontalComboBox, "Right", UiText("Right", "右"));
            SetComboItemContent(BackgroundVerticalComboBox, "Top", UiText("Top", "上"));
            SetComboItemContent(BackgroundVerticalComboBox, "Center", UiText("Center", "居中"));
            SetComboItemContent(BackgroundVerticalComboBox, "Bottom", UiText("Bottom", "下"));

            MessageBubblesHeaderText.Text = UiText("Message Bubbles", "消息气泡");
            BubbleColorComboBox.Header = UiText("Bubble color", "气泡颜色");
            SetComboItemContent(BubbleColorComboBox, "SoftGray", UiText("Soft gray", "柔和灰"));
            SetComboItemContent(BubbleColorComboBox, "Parchment", UiText("Warm parchment", "暖羊皮纸"));
            SetComboItemContent(BubbleColorComboBox, "PaleBlue", UiText("Pale blue", "淡蓝"));
            SetComboItemContent(BubbleColorComboBox, "Crimson", UiText("Muted crimson", "暗红"));
            BubbleOpacitySlider.Header = UiText("Bubble opacity", "气泡透明度");

            MessageTextHeaderText.Text = UiText("Message Text", "消息文字");
            MessageTextColorComboBox.Header = UiText("Text color", "文字颜色");
            MessageFontComboBox.Header = UiText("Font", "字体");
            MessageFontSizeSlider.Header = UiText("Message font size", "消息字号");
            LabelsHeaderText.Text = UiText("Labels", "标签");
            MetaTextColorComboBox.Header = UiText("Label color", "标签颜色");
            MetaFontComboBox.Header = UiText("Label font", "标签字体");
            MetaFontSizeSlider.Header = UiText("Label font size", "标签字号");

            foreach (var combo in new[] { MessageTextColorComboBox, MetaTextColorComboBox })
            {
                SetComboItemContent(combo, "Auto", UiText("Auto", "自动"));
                SetComboItemContent(combo, "Muted", UiText("Muted", "柔和"));
                SetComboItemContent(combo, "Ink", UiText("Ink", "墨色"));
                SetComboItemContent(combo, "White", UiText("White", "白色"));
                SetComboItemContent(combo, "Crimson", UiText("Crimson", "绯红"));
                SetComboItemContent(combo, "Gold", UiText("Gold", "金色"));
            }
            foreach (var combo in new[] { MessageFontComboBox, MetaFontComboBox })
            {
                SetComboItemContent(combo, "Default", UiText("Default", "默认"));
                SetComboItemContent(combo, "Serif", UiText("Serif", "衬线"));
                SetComboItemContent(combo, "Mono", UiText("Mono", "等宽"));
            }

            RestoreComboSelection(SendModeBox, selectedSendMode);
            RestoreComboSelection(ThemeComboBox, selectedTheme);
            RestoreComboSelection(SkillLanguageComboBox, selectedLanguage);
            RestoreComboSelection(BackgroundHorizontalComboBox, selectedBackgroundX);
            RestoreComboSelection(BackgroundVerticalComboBox, selectedBackgroundY);
            RestoreComboSelection(BubbleColorComboBox, selectedBubbleColor);
            RestoreComboSelection(MessageTextColorComboBox, selectedMessageTextColor);
            RestoreComboSelection(MessageFontComboBox, selectedMessageFont);
            RestoreComboSelection(MetaTextColorComboBox, selectedMetaTextColor);
            RestoreComboSelection(MetaFontComboBox, selectedMetaFont);
            UpdateSendButtonContent();

            if (refreshMessages)
            {
                RefreshMessageTextStyles();
            }
            RefreshRoomPanel();
            RefreshParticipants();
            RootGrid.UpdateLayout();
        }
        finally
        {
            refreshingLanguage = false;
        }
    }

    private static void SetComboItemContent(ComboBox? comboBox, string tag, string content)
    {
        if (comboBox is null) return;
        foreach (var item in comboBox.Items.OfType<ComboBoxItem>())
        {
            if (string.Equals(item.Tag?.ToString(), tag, StringComparison.OrdinalIgnoreCase))
            {
                item.Content = content;
                return;
            }
        }
    }

    private void UpdateSendButtonContent()
    {
        if (SendButton is null) return;
        if (voiceRecording)
        {
            SendButton.Content = UiText("Release", "松开");
            return;
        }
        SendButton.Content = SelectedSendMode() == "Voice"
            ? UiText("Hold", "按住")
            : UiText("Send", "发送");
    }

    private static void RestoreComboSelection(ComboBox? comboBox, string tag)
    {
        if (comboBox is null || string.IsNullOrWhiteSpace(tag)) return;
        foreach (var item in comboBox.Items.OfType<ComboBoxItem>())
        {
            if (string.Equals(item.Tag?.ToString(), tag, StringComparison.OrdinalIgnoreCase))
            {
                comboBox.SelectedItem = null;
                comboBox.SelectedItem = item;
                comboBox.UpdateLayout();
                return;
            }
        }
    }

    private void SaveAppConfigIfReady()
    {
        if (!settingsReady) return;

        try
        {
            var builder = new StringBuilder();
            builder.AppendLine("# SecureChat user settings. Delete this file to reset the UI.");
            builder.AppendLine("[chat]");
            AppendYaml(builder, "theme", ComboTag(ThemeComboBox));
            AppendYaml(builder, "language", ComboTag(SkillLanguageComboBox));
            AppendYaml(builder, "infobar_seconds", NumberString(InfoBarSecondsSlider.Value));
            AppendYaml(builder, "settings_panel_opacity", NumberString(SettingsPanelOpacitySlider.Value));
            AppendYaml(builder, "show_only_messages", showOnlyMessages ? "true" : "false");
            AppendYaml(builder, "auto_preview_images", autoPreviewImages ? "true" : "false");
            AppendYaml(builder, "auto_load_audio", autoLoadAudio ? "true" : "false");
            AppendYaml(builder, "member_default_nickname", MemberDefaultNicknameBox.Text.Trim());
            AppendYaml(builder, "local_server_tls_ca", LocalServerTlsCaBox.Text.Trim());
            AppendYaml(builder, "chat_background_path", chatBackgroundPath ?? "");
            AppendYaml(builder, "chat_background_opacity", NumberString(BackgroundOpacitySlider.Value));
            AppendYaml(builder, "chat_background_crop_x", ComboTag(BackgroundHorizontalComboBox));
            AppendYaml(builder, "chat_background_crop_y", ComboTag(BackgroundVerticalComboBox));
            AppendYaml(builder, "bubble_color", ComboTag(BubbleColorComboBox));
            AppendYaml(builder, "bubble_opacity", NumberString(BubbleOpacitySlider.Value));
            AppendYaml(builder, "message_text_color", ComboTag(MessageTextColorComboBox));
            AppendYaml(builder, "message_font", ComboTag(MessageFontComboBox));
            AppendYaml(builder, "message_font_size", NumberString(MessageFontSizeSlider.Value));
            AppendYaml(builder, "label_text_color", ComboTag(MetaTextColorComboBox));
            AppendYaml(builder, "label_font", ComboTag(MetaFontComboBox));
            AppendYaml(builder, "label_font_size", NumberString(MetaFontSizeSlider.Value));
            builder.AppendLine();
            builder.AppendLine("[pool]");
            var poolUrls = ReadPoolUrlsFromConfig(AppConfigPath());
            if (poolUrls.Count == 0) poolUrls.Add("wss://chat.example.online:25566");
            foreach (var url in poolUrls)
            {
                builder.AppendLine(url);
            }

            File.WriteAllText(AppConfigPath(), builder.ToString(), Encoding.UTF8);
        }
        catch
        {
        }
    }

    private void LoadAppConfig()
    {
        try
        {
            var configPath = AppConfigPath();
            if (!File.Exists(configPath)) return;

            var config = ReadAppConfig(configPath);
            var chatValues = config.Section("chat");
            if (chatValues.Count == 0) return;

            SetComboByTag(ThemeComboBox, Value(chatValues, "theme", "Light"));
            SetComboByTag(SkillLanguageComboBox, Value(chatValues, "language", "Chinese"));
            SetSlider(InfoBarSecondsSlider, Value(chatValues, "infobar_seconds", "5"));
            SetSlider(SettingsPanelOpacitySlider, Value(chatValues, "settings_panel_opacity", "0.99"));
            showOnlyMessages = Value(chatValues, "show_only_messages", "true").Equals("true", StringComparison.OrdinalIgnoreCase);
            ShowOnlyMessagesToggleSwitch.IsOn = showOnlyMessages;
            autoPreviewImages = Value(chatValues, "auto_preview_images", "true").Equals("true", StringComparison.OrdinalIgnoreCase);
            autoLoadAudio = Value(chatValues, "auto_load_audio", "false").Equals("true", StringComparison.OrdinalIgnoreCase);
            AutoPreviewImagesToggleSwitch.IsOn = autoPreviewImages;
            AutoLoadAudioToggleSwitch.IsOn = autoLoadAudio;
            MemberDefaultNicknameBox.Text = Value(chatValues, "member_default_nickname", "");
            LocalServerTlsCaBox.Text = Value(chatValues, "local_server_tls_ca", "");
            SetSlider(BackgroundOpacitySlider, Value(chatValues, "chat_background_opacity", "0.28"));
            SetComboByTag(BackgroundHorizontalComboBox, Value(chatValues, "chat_background_crop_x", "Center"));
            SetComboByTag(BackgroundVerticalComboBox, Value(chatValues, "chat_background_crop_y", "Center"));
            SetComboByTag(BubbleColorComboBox, Value(chatValues, "bubble_color", "SoftGray"));
            SetSlider(BubbleOpacitySlider, Value(chatValues, "bubble_opacity", "1"));
            SetComboByTag(MessageTextColorComboBox, Value(chatValues, "message_text_color", "Auto"));
            SetComboByTag(MessageFontComboBox, Value(chatValues, "message_font", "Default"));
            SetSlider(MessageFontSizeSlider, Value(chatValues, "message_font_size", "14"));
            SetComboByTag(MetaTextColorComboBox, Value(chatValues, "label_text_color", "Auto"));
            SetComboByTag(MetaFontComboBox, Value(chatValues, "label_font", "Default"));
            SetSlider(MetaFontSizeSlider, Value(chatValues, "label_font_size", "11"));

            currentTheme = ComboTag(ThemeComboBox);
            uiLanguage = ComboTag(SkillLanguageComboBox);
            ApplyLanguage();
            ApplyAppTheme(currentTheme);
            LoadChatBackgroundFromPath(Value(chatValues, "chat_background_path", ""));
            SettingsPanel.Opacity = SettingsPanelOpacitySlider.Value;
            UpdateBubbleStyleState();
            UpdateMessageTextStyleState();
            UpdateMetaTextStyleState();
            ApplyChatBackgroundSettings();
            RefreshMessageTextStyles();
        }
        catch
        {
        }
    }

    private static string AppConfigPath()
    {
        return Path.Combine(AppContext.BaseDirectory, "config.yml");
    }

    private sealed class AppConfig
    {
        private readonly Dictionary<string, Dictionary<string, string>> sections = new(StringComparer.OrdinalIgnoreCase);

        public Dictionary<string, string> Section(string name)
        {
            if (!sections.TryGetValue(name, out var section))
            {
                section = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                sections[name] = section;
            }

            return section;
        }
    }

    private static AppConfig ReadAppConfig(string path)
    {
        var config = new AppConfig();
        var values = config.Section("chat");
        foreach (var raw in File.ReadAllLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;

            if (line.Length > 2 && line[0] == '[' && line[^1] == ']')
            {
                var sectionName = line[1..^1].Trim();
                values = config.Section(string.IsNullOrWhiteSpace(sectionName) ? "chat" : sectionName);
                continue;
            }

            var separator = line.IndexOf(':');
            if (separator <= 0) continue;

            var key = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            values[key] = UnquoteYaml(value);
        }

        return config;
    }

    private static List<string> ReadPoolUrlsFromConfig(string path)
    {
        var urls = new List<string>();
        if (!File.Exists(path)) return urls;

        var inPool = false;
        foreach (var raw in File.ReadAllLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
            if (line.Length > 2 && line[0] == '[' && line[^1] == ']')
            {
                inPool = string.Equals(line[1..^1].Trim(), "pool", StringComparison.OrdinalIgnoreCase);
                continue;
            }
            if (!inPool) continue;
            if (line.StartsWith("wss://", StringComparison.OrdinalIgnoreCase))
            {
                urls.Add(line);
            }
        }

        return urls;
    }

    private static void AppendYaml(StringBuilder builder, string key, string value)
    {
        builder.Append(key).Append(": ").AppendLine(QuoteYaml(value));
    }

    private static string QuoteYaml(string value)
    {
        return "\"" + value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
    }

    private static string UnquoteYaml(string value)
    {
        if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
        {
            return value[1..^1]
                .Replace("\\\"", "\"", StringComparison.Ordinal)
                .Replace("\\\\", "\\", StringComparison.Ordinal);
        }

        return value;
    }

    private static string Value(Dictionary<string, string> values, string key, string fallback)
    {
        return values.TryGetValue(key, out var value) ? value : fallback;
    }

    private static string NumberString(double value)
    {
        return value.ToString("0.###", CultureInfo.InvariantCulture);
    }

    private static void SetSlider(Slider slider, string value)
    {
        if (!double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var number)) return;
        slider.Value = Math.Clamp(number, slider.Minimum, slider.Maximum);
    }

    private static void SetComboByTag(ComboBox comboBox, string tag)
    {
        foreach (var item in comboBox.Items.OfType<ComboBoxItem>())
        {
            if (string.Equals(item.Tag?.ToString(), tag, StringComparison.OrdinalIgnoreCase))
            {
                comboBox.SelectedItem = item;
                return;
            }
        }
    }

    private void MainPivot_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        MessageBox.Focus(FocusState.Programmatic);
    }

    private void SidebarResizeHandle_PointerPressed(object sender, PointerRoutedEventArgs e)
    {
        if (!sidebarVisible) return;
        resizingSidebar = true;
        SidebarResizeIndicator.Opacity = 0.7;
        SidebarResizeHandle.CapturePointer(e.Pointer);
        e.Handled = true;
    }

    private void SidebarResizeHandle_PointerMoved(object sender, PointerRoutedEventArgs e)
    {
        if (!resizingSidebar) return;

        var point = e.GetCurrentPoint(RootGrid).Position;
        SidebarColumn.Width = new GridLength(Math.Clamp(point.X, 260, 520));
        e.Handled = true;
    }

    private void SidebarResizeHandle_PointerReleased(object sender, PointerRoutedEventArgs e)
    {
        if (!resizingSidebar) return;

        resizingSidebar = false;
        SidebarResizeIndicator.Opacity = 0.28;
        SidebarResizeHandle.ReleasePointerCapture(e.Pointer);
        e.Handled = true;
    }

    private void SidebarResizeHandle_PointerEntered(object sender, PointerRoutedEventArgs e)
    {
        if (!sidebarVisible) return;
        SidebarResizeIndicator.Opacity = 0.28;
    }

    private void SidebarResizeHandle_PointerExited(object sender, PointerRoutedEventArgs e)
    {
        if (resizingSidebar) return;
        SidebarResizeIndicator.Opacity = 0;
    }

    private void SetWindowIcon()
    {
        var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "Chat.ico");
        if (File.Exists(iconPath))
        {
            AppWindow.SetIcon(iconPath);
        }
    }

    private void SetInitialWindowSize()
    {
        try
        {
            var scale = 1.0;
            var hwnd = WindowNative.GetWindowHandle(this);
            if (hwnd != IntPtr.Zero)
            {
                var dpi = GetDpiForWindow(hwnd);
                if (dpi > 0)
                {
                    scale = dpi / 96.0;
                }
            }

            AppWindow.Resize(new Windows.Graphics.SizeInt32(
                (int)Math.Round(InitialWindowWidth * scale),
                (int)Math.Round(InitialWindowHeight * scale)));
        }
        catch
        {
        }
    }

    [DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr hwnd);
}
