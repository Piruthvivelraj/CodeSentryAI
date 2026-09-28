window.codeSentryInterop = {
    scrollTerminalToBottom: function (elementId) {
        var el = document.getElementById(elementId || 'terminalLog');
        if (el) {
            el.scrollTop = el.scrollHeight;
        }
    },
    downloadFile: function (fileName, content) {
        var blob = new Blob([content], { type: 'application/json' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    },
    copyToClipboard: function (text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        }
        // Fallback for non-HTTPS contexts
        var textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        try { document.execCommand('copy'); } catch (e) { }
        document.body.removeChild(textarea);
        return Promise.resolve();
    },
    // Keyboard shortcut registration — uses DOM button clicks, no DotNetObjectReference needed
    registerKeyboardShortcuts: function (scanButtonId, cancelButtonId) {
        if (window._codeSentryKeyHandler) {
            document.removeEventListener('keydown', window._codeSentryKeyHandler);
        }
        window._codeSentryKeyHandler = function (e) {
            // Ctrl+Enter (or Cmd+Enter on Mac) — trigger scan
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                var btn = scanButtonId ? document.getElementById(scanButtonId) : null;
                if (btn && !btn.disabled) btn.click();
            }
            // Escape — cancel scan (only if a cancel button exists and is visible)
            if (e.key === 'Escape') {
                var cancelBtn = cancelButtonId ? document.getElementById(cancelButtonId) : null;
                if (cancelBtn && !cancelBtn.hidden) cancelBtn.click();
            }
        };
        document.addEventListener('keydown', window._codeSentryKeyHandler);
    },
    unregisterKeyboardShortcuts: function () {
        if (window._codeSentryKeyHandler) {
            document.removeEventListener('keydown', window._codeSentryKeyHandler);
            window._codeSentryKeyHandler = null;
        }
    },
    downloadPdf: function (filename, base64) {
        const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
        const blob = new Blob([bytes], { type: 'application/pdf' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    },
    countUp: function(elementId, target, duration) {
        const el = document.getElementById(elementId);
        if (!el) return;
        let start = 0;
        const step = target / (duration / 16);
        const timer = setInterval(() => {
            start += step;
            if (start >= target) { el.textContent = target; clearInterval(timer); return; }
            el.textContent = Math.floor(start);
        }, 16);
    },
    initScrollAnimations: function() {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-visible');
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.15 });
        document.querySelectorAll('.scroll-animate').forEach(el => observer.observe(el));
    },
    initNavbarScroll: function() {
        window.addEventListener('scroll', () => {
            const nav = document.querySelector('nav');
            if (!nav) return;
            if (window.scrollY > 50) {
                nav.classList.add('nav-scrolled');
            } else {
                nav.classList.remove('nav-scrolled');
            }
        });
    }
};

window.codeSentryToast = {
    create: function (id, type, message) {
        let container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            container.className = 'fixed bottom-4 right-4 z-50 flex flex-col gap-2';
            document.body.appendChild(container);
        }

        const toast = document.createElement('div');
        toast.id = 'toast-' + id;
        
        let bgColor = type === 'error' ? 'bg-error text-white' : type === 'success' ? 'bg-tertiary text-on-surface' : 'bg-primary text-white';
        let icon = type === 'error' ? 'error' : type === 'success' ? 'check_circle' : 'info';

        toast.className = `flex items-center gap-3 px-4 py-3 rounded shadow-lg transition-all transform translate-y-2 opacity-0 ${bgColor}`;
        toast.innerHTML = `<span class="material-symbols-outlined">${icon}</span><span class="font-data-sm">${message}</span>`;
        
        container.appendChild(toast);
        
        // Trigger animation
        setTimeout(() => {
            toast.classList.remove('translate-y-2', 'opacity-0');
            toast.classList.add('translate-y-0', 'opacity-100');
        }, 10);
    },
    dismiss: function (id) {
        const toast = document.getElementById('toast-' + id);
        if (toast) {
            toast.classList.remove('translate-y-0', 'opacity-100');
            toast.classList.add('translate-y-2', 'opacity-0');
            setTimeout(() => {
                if (toast.parentElement) {
                    toast.parentElement.removeChild(toast);
                }
            }, 300);
        }
    }
};
