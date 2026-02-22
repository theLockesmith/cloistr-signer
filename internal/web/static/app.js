// Cloistr Signer Web UI JavaScript

// Button loading state utilities
const ButtonState = {
    setLoading(button, loadingText = 'Loading...') {
        button.disabled = true;
        button.dataset.originalText = button.textContent;
        button.textContent = loadingText;
        button.classList.add('loading');
    },

    reset(button) {
        button.disabled = false;
        if (button.dataset.originalText) {
            button.textContent = button.dataset.originalText;
            delete button.dataset.originalText;
        }
        button.classList.remove('loading');
    }
};

// Modal Enter key support - call this for each modal form
function enableEnterSubmit(modal, form) {
    modal.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey && e.target.tagName !== 'TEXTAREA') {
            e.preventDefault();
            const submitBtn = form.querySelector('button[type="submit"], button.btn-primary:last-child');
            if (submitBtn && !submitBtn.disabled) {
                submitBtn.click();
            }
        }
    });
}

// Utility functions
const API = {
    async request(method, url, data = null) {
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        if (data) {
            options.body = JSON.stringify(data);
        }

        const response = await fetch(url, options);
        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Request failed');
        }

        return result;
    },

    get(url) {
        return this.request('GET', url);
    },

    post(url, data) {
        return this.request('POST', url, data);
    },

    delete(url) {
        return this.request('DELETE', url);
    }
};

// NIP-07 helpers
const NIP07 = {
    async isAvailable() {
        // Wait a bit for extension to inject
        await new Promise(resolve => setTimeout(resolve, 100));
        return !!window.nostr;
    },

    async getPublicKey() {
        if (!window.nostr) throw new Error('NIP-07 extension not found');
        return await window.nostr.getPublicKey();
    },

    async signEvent(event) {
        if (!window.nostr) throw new Error('NIP-07 extension not found');
        return await window.nostr.signEvent(event);
    },

    async createChallenge() {
        const challenge = 'cloistr-auth-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
        return challenge;
    }
};

// Toast notifications
const Toast = {
    show(message, type = 'info', duration = 3000) {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;

        document.body.appendChild(toast);

        // Trigger animation
        setTimeout(() => toast.classList.add('show'), 10);

        // Remove after duration
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, duration);
    },

    success(message) {
        this.show(message, 'success');
    },

    error(message) {
        this.show(message, 'error');
    }
};

// Add toast styles dynamically
const toastStyles = document.createElement('style');
toastStyles.textContent = `
    .toast {
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 12px 24px;
        border-radius: 6px;
        background: var(--bg-tertiary);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        opacity: 0;
        transform: translateY(20px);
        transition: all 0.3s ease;
        z-index: 9999;
    }
    .toast.show {
        opacity: 1;
        transform: translateY(0);
    }
    .toast-success {
        background: rgba(63, 185, 80, 0.9);
        border-color: var(--accent-success);
    }
    .toast-error {
        background: rgba(248, 81, 73, 0.9);
        border-color: var(--accent-danger);
    }
`;
document.head.appendChild(toastStyles);

// Logout is handled server-side at /logout
// The auth_token cookie is HttpOnly so JavaScript cannot clear it

// Format relative time
function formatRelativeTime(date) {
    const now = new Date();
    const diff = date - now;

    if (diff < 0) return 'expired';

    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        Toast.success('Copied to clipboard');
    }).catch(() => {
        Toast.error('Failed to copy');
    });
}
