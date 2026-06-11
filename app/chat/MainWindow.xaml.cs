using Microsoft.UI.Dispatching;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Windows.Storage.Pickers;
using Windows.UI;
using WinRT.Interop;

namespace chat;

public sealed partial class MainWindow : Window
{
    private enum SessionMode
    {
        None,
        Host,
        Join
    }

    private readonly NativeMethods.ChatEventCallback callback;
    private readonly DispatcherQueue dispatcherQueue;
    private readonly DispatcherTimer infoBarTimer = new();
    private readonly HashSet<string> participants = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Queue<string>> pendingAttachmentSenders = new(StringComparer.OrdinalIgnoreCase);
    private SessionMode sessionMode = SessionMode.None;
    private bool sidebarVisible = true;
    private bool resizingSidebar;
    private bool settingsHiding;
    private bool showOnlyOwnMessages;
    private bool settingsReady;
    private bool refreshingLanguage;
    private bool infoBarFading;
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

    private static readonly NativeMethods.ChatEventCallback NoOpCallback = (_, _, _) => { };
    private sealed record BubbleVisibilityState(bool IsFilterable, bool IsOwn);
    private sealed record ChatDisplayLine(string Kind, string Sender, string Body, bool IsOwn, bool IsFilterable);
    private const int InitialWindowWidth = 1180;
    private const int InitialWindowHeight = 760;

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

        var kind = Marshal.PtrToStringUTF8(kindPtr) ?? "status";
        var message = Marshal.PtrToStringUTF8(messagePtr) ?? "";
        dispatcherQueue.TryEnqueue(() =>
        {
            if (!isClosing) AddLine(kind, message);
        });
    }

    private void MainWindow_Closed(object sender, WindowEventArgs args)
    {
        if (isClosing) return;
        isClosing = true;
        infoBarTimer.Stop();

        try
        {
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
                Environment.Exit(0);
            }
        });

        // Native WebSocket shutdown can occasionally wait on network teardown. Keep
        // the UI close path bounded so the window does not appear stuck.
        System.Threading.Tasks.Task.Run(async () =>
        {
            await System.Threading.Tasks.Task.Delay(1200);
            Environment.Exit(0);
        });
    }

    private void Host_Click(object sender, RoutedEventArgs e)
    {
        var serverUrl = HostServerUrlBox.Text.Trim();
        if (serverUrl.Length == 0)
        {
            AddLine("error", "Server URL is required.");
            return;
        }

        // Host is a participant now; only Server owns listening and TLS setup.
        var ok = NativeMethods.chat_host_start(
            serverUrl,
            HostRoomBox.Text.Trim(),
            HostUserBox.Text.Trim(),
            HostPasswordBox.Password);
        if (ok != 0)
        {
            roomName = HostRoomBox.Text.Trim();
            participants.Clear();
            AddParticipant(HostUserBox.Text.Trim());
            SetSessionMode(SessionMode.Host);
        }
    }

    private void Join_Click(object sender, RoutedEventArgs e)
    {
        var ok = NativeMethods.chat_join_start(
            JoinUrlBox.Text.Trim(),
            JoinRoomBox.Text.Trim(),
            JoinUserBox.Text.Trim(),
            JoinPasswordBox.Password);
        if (ok != 0)
        {
            roomName = JoinRoomBox.Text.Trim();
            participants.Clear();
            AddParticipant(JoinUserBox.Text.Trim());
            SetSessionMode(SessionMode.Join);
        }
    }

    private void Stop_Click(object sender, RoutedEventArgs e)
    {
        StopSession();
    }

    private void Send_Click(object sender, RoutedEventArgs e)
    {
        SendSelectedMode();
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
            _ = SendPickedFileAsync(FileKind.Voice);
            return;
        }

        SendCurrentMessage();
    }

    private void SendCurrentMessage()
    {
        var text = MessageBox.Text.Trim();
        if (text.Length == 0) return;

        if (text.Equals("/clear", StringComparison.OrdinalIgnoreCase))
        {
            MessagesPanel.Children.Clear();
            MessageBox.Text = "";
            return;
        }

        if (NativeMethods.chat_send_line(text) != 0)
        {
            MessageBox.Text = "";
        }
    }

    private enum FileKind
    {
        Image,
        File,
        Voice
    }

    private async System.Threading.Tasks.Task SendPickedFileAsync(FileKind kind)
    {
        var file = await PickFileAsync(kind);
        if (file is null) return;

        _ = kind switch
        {
            FileKind.Image => NativeMethods.chat_send_image(file.Path),
            FileKind.File => NativeMethods.chat_send_file(file.Path),
            FileKind.Voice => NativeMethods.chat_send_voice(file.Path),
            _ => 0
        };
    }

    private async System.Threading.Tasks.Task<Windows.Storage.StorageFile?> PickFileAsync(FileKind kind)
    {
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
            case FileKind.Voice:
                picker.FileTypeFilter.Add(".wav");
                break;
            default:
                picker.FileTypeFilter.Add(".txt");
                picker.FileTypeFilter.Add(".md");
                picker.FileTypeFilter.Add(".markdown");
                picker.FileTypeFilter.Add(".log");
                picker.FileTypeFilter.Add(".csv");
                picker.FileTypeFilter.Add(".json");
                picker.FileTypeFilter.Add(".xml");
                picker.FileTypeFilter.Add(".yml");
                picker.FileTypeFilter.Add(".yaml");
                picker.FileTypeFilter.Add(".ini");
                picker.FileTypeFilter.Add(".conf");
                picker.FileTypeFilter.Add(".cfg");
                break;
        }

        return await picker.PickSingleFileAsync();
    }

    private void AddLine(string kind, string message)
    {
        UpdateSessionStatus(kind, message);
        UpdateParticipants(kind, message);

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
        if (string.Equals(kind, "log", StringComparison.OrdinalIgnoreCase)) return true;
        if (!string.Equals(kind, "status", StringComparison.OrdinalIgnoreCase)) return false;

        // GUI status is intentionally user-facing only. Endpoint details
        // stay in CLI/log paths so the chat area does not expose network internals.
        return message.StartsWith("client ws://", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("client wss://", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("Clients can join with:", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("endpoint", StringComparison.OrdinalIgnoreCase);
    }

    private bool TryRenderAttachment(string kind, string path)
    {
        if (kind == "image")
        {
            var sender = TakeAttachmentSender(kind);
            var image = new Image
            {
                Source = new BitmapImage(new Uri(path)),
                Stretch = Stretch.Uniform,
                MaxWidth = 360,
                MaxHeight = 260
            };
            RenderBubble("image", sender, image, SenderOwnsAttachment(sender, path), true);
            return true;
        }

        if (kind == "voice")
        {
            var sender = TakeAttachmentSender(kind);
            var player = new MediaPlayerElement
            {
                Source = Windows.Media.Core.MediaSource.CreateFromUri(new Uri(path)),
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
            RenderBubble("voice", sender, player, SenderOwnsAttachment(sender, path), true);
            return true;
        }

        return false;
    }

    private bool SenderOwnsAttachment(string sender, string path)
    {
        return string.IsNullOrWhiteSpace(sender) ? IsOwnAttachmentPath(path) : IsOwnSender(sender);
    }

    private void RememberAttachmentSender(string type, string sender)
    {
        if (string.IsNullOrWhiteSpace(sender)) return;

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
            queue = new Queue<string>();
            pendingAttachmentSenders[kind] = queue;
        }
        queue.Enqueue(sender);
    }

    private string TakeAttachmentSender(string kind)
    {
        if (!pendingAttachmentSenders.TryGetValue(kind, out var queue) || queue.Count == 0)
        {
            return "";
        }
        return queue.Dequeue();
    }

    private bool IsOwnAttachmentPath(string path)
    {
        return !path.Contains("\\logs\\", StringComparison.OrdinalIgnoreCase) &&
            !path.Contains("/logs/", StringComparison.OrdinalIgnoreCase);
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
            Tag = new BubbleVisibilityState(isFilterable, isOwnSender),
            Visibility = showOnlyOwnMessages && isFilterable && !isOwnSender
                ? Visibility.Collapsed
                : Visibility.Visible
        };
        row.Children.Add(group);
        MessagesPanel.Children.Add(row);

        MessagesScrollViewer.UpdateLayout();
        MessagesScrollViewer.ChangeView(null, MessagesScrollViewer.ScrollableHeight, null);
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
        var body = message;
        if (displayKind == "message")
        {
            try
            {
                using var document = JsonDocument.Parse(message);
                var root = document.RootElement;
                var type = root.TryGetProperty("type", out var typeValue) ? typeValue.GetString() ?? "" : "";
                var from = root.TryGetProperty("from", out var fromValue) ? fromValue.GetString() ?? "" : "";
                if (root.TryGetProperty("payload", out var payload) &&
                    payload.ValueKind == JsonValueKind.Object &&
                    payload.TryGetProperty("displayName", out var displayName))
                {
                    from = displayName.GetString() ?? from;
                }

                if (type == "text")
                {
                    body = root.TryGetProperty("content", out var content) ? content.GetString() ?? "" : "";
                    sender = from;
                }
                else if (type.EndsWith("_meta", StringComparison.OrdinalIgnoreCase))
                {
                    var name = root.TryGetProperty("name", out var nameValue) ? nameValue.GetString() ?? "" : "";
                    sender = from;
                    RememberAttachmentSender(type, sender);
                    body = type == "file_meta"
                        ? $"sent file {name}"
                        : "";
                }
            }
            catch
            {
            }
        }

        return new ChatDisplayLine(displayKind, sender, body, IsOwnSender(sender), displayKind == "message");
    }

    private bool IsOwnSender(string sender)
    {
        var ownName = sessionMode switch
        {
            SessionMode.Host => HostUserBox.Text.Trim(),
            SessionMode.Join => JoinUserBox.Text.Trim(),
            _ => ""
        };
        return ownName.Length > 0 && string.Equals(sender, ownName, StringComparison.OrdinalIgnoreCase);
    }

    private void SetSessionMode(SessionMode mode)
    {
        sessionMode = mode;
        HostButton.IsEnabled = mode == SessionMode.None;
        JoinButton.IsEnabled = mode == SessionMode.None;
        StopButton.IsEnabled = true;
        MessageBox.IsEnabled = mode != SessionMode.None;
        SendModeBox.IsEnabled = mode != SessionMode.None;
        if (mode == SessionMode.None)
        {
            roomName = "-";
        }
        RefreshRoomPanel();
    }

    private void StopSession()
    {
        NativeMethods.chat_stop();
        SetSessionMode(SessionMode.None);
        ResetParticipants();
    }

    private void UpdateSessionStatus(string kind, string message)
    {
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
            message == "Signaling connection ended" ||
            message == "Signaling failed" ||
            message == "Username already in room")
        {
            SetSessionMode(SessionMode.None);
            ResetParticipants();
            ShowInfo(message, message == "Username already in room" ? InfoBarSeverity.Error : InfoBarSeverity.Warning);
            return;
        }

        if (message.StartsWith("Host started", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("Room created: ", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("Clients can join", StringComparison.OrdinalIgnoreCase) ||
            message.StartsWith("Joined room", StringComparison.OrdinalIgnoreCase) ||
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
        if (kind != "status") return;

        const string membersPrefix = "Room members: ";
        if (message.StartsWith(membersPrefix, StringComparison.Ordinal))
        {
            participants.Clear();
            foreach (var name in message[membersPrefix.Length..]
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                participants.Add(name);
            }
            RefreshParticipants();
            return;
        }

        AddStatusName(message, "Client joined: ");
        AddStatusName(message, "Player joined: ");
        RemoveStatusName(message, "Client left: ");
        RemoveStatusName(message, "Player left: ");
    }

    private void AddStatusName(string message, string prefix)
    {
        if (!message.StartsWith(prefix, StringComparison.Ordinal)) return;
        AddParticipant(message[prefix.Length..].Trim());
    }

    private void RemoveStatusName(string message, string prefix)
    {
        if (!message.StartsWith(prefix, StringComparison.Ordinal)) return;
        participants.Remove(message[prefix.Length..].Trim());
        RefreshParticipants();
    }

    private void AddParticipant(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return;
        participants.Add(name.Trim());
        RefreshParticipants();
    }

    private void ResetParticipants()
    {
        participants.Clear();
        RefreshParticipants();
    }

    private void RefreshParticipants()
    {
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
            RoomParticipantsPanel.Children.Add(new Border
            {
                Padding = new Thickness(10, 7, 10, 7),
                Background = new SolidColorBrush(Color.FromArgb(20, 0, 0, 0)),
                CornerRadius = new CornerRadius(6),
                Child = new TextBlock
                {
                    Text = name,
                    TextWrapping = TextWrapping.Wrap
                }
            });
        }
        RefreshRoomPanel();
    }

    private void RefreshRoomPanel()
    {
        if (RoomModeText is null || RoomNameText is null) return;

        var mode = sessionMode switch
        {
            SessionMode.Host => UiText("server", "服务端"),
            SessionMode.Join => UiText("client", "客户端"),
            _ => UiText("not connected", "未连接")
        };
        RoomModeText.Text = $"{UiText("Mode", "模式")}: {mode}";
        RoomNameText.Text = $"{UiText("Room", "房间")}: {roomName}";
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

    private void ShowOnlyOwnToggleSwitch_Toggled(object sender, RoutedEventArgs e)
    {
        showOnlyOwnMessages = ShowOnlyOwnToggleSwitch.IsOn;
        RefreshBubbleVisibility();
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
        ChatBackgroundWash.Background = new SolidColorBrush(chat);
        SidebarToggleIcon.Source = new BitmapImage(new Uri(Path.Combine(
            AppContext.BaseDirectory,
            "Assets",
            isDark ? "sidebar_toggle_inverted.png" : "sidebar_toggle.png")));
        StopIcon.Stroke = new SolidColorBrush(foreground);
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
            row.Visibility = showOnlyOwnMessages && state.IsFilterable && !state.IsOwn
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
            HostServerUrlBox.Header = UiText("Server URL", "服务器 URL");
            HostUserBox.Header = UiText("User", "用户");
            HostPasswordBox.Header = UiText("Password", "密码");
            HostButton.Content = UiText("Start Hosting", "启动房间");
            JoinUrlBox.Header = UiText("URL", "地址");
            JoinRoomBox.Header = UiText("Room", "房间");
            JoinUserBox.Header = UiText("User", "用户");
            JoinPasswordBox.Header = UiText("Password", "密码");
            JoinButton.Content = UiText("Join Room", "加入房间");
            RoomStatusHeaderText.Text = UiText("Room Status", "房间状态");
            RoomParticipantsHeaderText.Text = UiText("Participants", "参与者");

            MessageBox.PlaceholderText = UiText("Type a message", "输入消息");
            SendButton.Content = UiText("Send", "发送");
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
            ShowOnlyOwnToggleSwitch.Header = UiText("Only my messages", "只看自己");
            ShowOnlyOwnToggleSwitch.OnContent = UiText("On", "开");
            ShowOnlyOwnToggleSwitch.OffContent = UiText("Off", "关");
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
            AppendYaml(builder, "show_only_own", showOnlyOwnMessages ? "true" : "false");
            AppendYaml(builder, "host_server_url", HostServerUrlBox.Text.Trim());
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
            showOnlyOwnMessages = Value(chatValues, "show_only_own", "false").Equals("true", StringComparison.OrdinalIgnoreCase);
            ShowOnlyOwnToggleSwitch.IsOn = showOnlyOwnMessages;
            HostServerUrlBox.Text = Value(chatValues, "host_server_url", "ws://127.0.0.1:25566");
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
