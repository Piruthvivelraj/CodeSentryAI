using System;
using System.Collections.Generic;
using Microsoft.JSInterop;

namespace CodeSentryAI.Services;

public class ToastService : IDisposable
{
    private readonly IJSRuntime _js;
    private readonly List<string> _activeToasts = new();
    private bool _disposed;

    public ToastService(IJSRuntime js)
    {
        _js = js;
    }

    public void ShowSuccess(string message)
    {
        _ = Show("success", message);
    }

    public void ShowError(string message)
    {
        _ = Show("error", message);
    }

    public void ShowInfo(string message)
    {
        _ = Show("info", message);
    }

    private async System.Threading.Tasks.Task Show(string type, string message)
    {
        if (_disposed) return;
        var id = Guid.NewGuid().ToString("N");
        _activeToasts.Add(id);
        try
        {
            await _js.InvokeVoidAsync("codeSentryToast.create", id, type, message);
            await System.Threading.Tasks.Task.Delay(3000);
            if (!_disposed)
            {
                await _js.InvokeVoidAsync("codeSentryToast.dismiss", id);
                _activeToasts.Remove(id);
            }
        }
        catch
        {
            _activeToasts.Remove(id);
        }
    }

    public async System.Threading.Tasks.Task CopyToClipboard(string text, string label = "Copied!")
    {
        try
        {
            await _js.InvokeVoidAsync("navigator.clipboard.writeText", text);
            ShowSuccess(label);
        }
        catch
        {
            ShowError("Copy failed");
        }
    }

    public void Dispose()
    {
        _disposed = true;
        foreach (var id in _activeToasts)
        {
            try { _js.InvokeVoidAsync("codeSentryToast.dismiss", id); } catch { }
        }
        _activeToasts.Clear();
    }
}
