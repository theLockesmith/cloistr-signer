// Cloistr Signer Tutorial System
// Uses Shepherd.js for guided tours
// Tutorial data is JSON-exportable for React Native compatibility

(function() {
    'use strict';

    // Tutorial content definitions (JSON-exportable for React Native)
    const TUTORIALS = {
        'create-first-key': {
            id: 'create-first-key',
            name: 'Creating Your First Key',
            description: 'Learn how to create a new Nostr signing key',
            page: '/keys',
            steps: [
                {
                    target: '#create-key-btn',
                    title: 'Create a Key',
                    text: 'Click this button to generate a new Nostr signing key. The private key is generated securely and stored encrypted.',
                    position: 'bottom'
                },
                {
                    target: '#key-name',
                    title: 'Name Your Key',
                    text: 'Give your key a memorable name like "Main Key" or "Work Account". This helps you identify it later.',
                    position: 'bottom',
                    waitFor: '#create-modal[style*="flex"]'
                },
                {
                    target: '.modal-actions button[type="submit"]',
                    title: 'Create',
                    text: 'Click Create to generate your key. The signer will create a new keypair and store the private key encrypted.',
                    position: 'top',
                    waitFor: '#create-modal[style*="flex"]'
                }
            ]
        },
        'bunker-signin': {
            id: 'bunker-signin',
            name: 'Bunker Sign-ins',
            description: 'Connect your key to Nostr apps using bunker:// URIs',
            page: '/keys',
            steps: [
                {
                    target: '.connect-btn',
                    title: 'Connect to an App',
                    text: 'Click Connect on any key to get a bunker:// URI. Apps like Amethyst, Damus, and Coracle use this to sign events with your key.',
                    position: 'bottom'
                },
                {
                    target: '#bunker-uri',
                    title: 'Copy the Bunker URI',
                    text: 'This URI contains your public key and the relays where the signer listens. Copy it and paste into your Nostr app\'s login screen.',
                    position: 'bottom',
                    waitFor: '#connect-modal[style*="flex"]'
                },
                {
                    target: '.connect-tab[data-tab="paste"]',
                    title: 'Or Paste from App',
                    text: 'Some apps give you a nostrconnect:// URI instead. Switch to this tab and paste it here to connect.',
                    position: 'bottom',
                    waitFor: '#connect-modal[style*="flex"]'
                }
            ]
        },
        'proxy-keys': {
            id: 'proxy-keys',
            name: 'Proxy Keys',
            description: 'Chain signers together without exposing private keys',
            page: '/keys',
            steps: [
                {
                    target: '#add-proxy-btn',
                    title: 'Add a Proxy Key',
                    text: 'A proxy key forwards signing requests to another signer. You never hold the private key - just a connection to the upstream bunker.',
                    position: 'bottom'
                },
                {
                    target: '#proxy-uri',
                    title: 'Enter the Bunker URI',
                    text: 'Paste the bunker:// URI from the upstream signer. This could be your nsecBunker, another Cloistr instance, or any NIP-46 compatible signer.',
                    position: 'bottom',
                    waitFor: '#proxy-modal[style*="flex"]'
                },
                {
                    target: '#proxy-step-success',
                    title: 'Grant Access Upstream',
                    text: 'After creating the proxy, you\'ll get a pubkey. The upstream signer admin needs to "Grant Access" to this pubkey before signing works.',
                    position: 'top',
                    waitFor: '#proxy-step-success:not([style*="none"])'
                }
            ]
        },
        'frost-signing': {
            id: 'frost-signing',
            name: 'FROST Threshold Signing',
            description: 'Split keys across multiple signers for enhanced security',
            page: '/frost',
            steps: [
                {
                    target: '#create-frost-btn, #initiate-dkg-btn',
                    title: 'Create a FROST Key',
                    text: 'FROST lets you split a key into multiple shares. For example, a 2-of-3 setup means any 2 of 3 share holders can sign together.',
                    position: 'bottom'
                },
                {
                    target: '#frost-threshold',
                    title: 'Set the Threshold',
                    text: 'The threshold is how many shares are needed to sign. A 2-of-3 setup: 3 total shares, 2 required. If one is lost, you can still sign.',
                    position: 'right',
                    waitFor: '#frost-modal[style*="flex"], #dkg-modal[style*="flex"]'
                },
                {
                    target: '#frost-participants, #dkg-participants',
                    title: 'Add Participants',
                    text: 'For distributed FROST, add the pubkeys of other signers who will hold shares. They\'ll participate in key generation via encrypted Nostr DMs.',
                    position: 'right',
                    waitFor: '#frost-modal[style*="flex"], #dkg-modal[style*="flex"]'
                }
            ]
        },
        'connect-to-app': {
            id: 'connect-to-app',
            name: 'Connecting to Apps',
            description: 'Two ways to connect: bunker:// and nostrconnect://',
            page: '/keys',
            steps: [
                {
                    target: '#connect-app-btn',
                    title: 'Connect to App',
                    text: 'Use this when an app shows you a nostrconnect:// URI or QR code. You\'re initiating the connection FROM the signer.',
                    position: 'bottom'
                },
                {
                    target: '.connect-btn',
                    title: 'Share bunker:// URI',
                    text: 'Alternatively, click Connect on a key to get a bunker:// URI. The app initiates the connection TO your signer.',
                    position: 'bottom'
                },
                {
                    target: '.connect-tab[data-tab="share"]',
                    title: 'bunker:// Method',
                    text: 'Copy this URI and paste into apps like Amethyst, Damus, or Coracle. The app connects to your signer through the listed relays.',
                    position: 'bottom',
                    waitFor: '#connect-modal[style*="flex"]'
                },
                {
                    target: '.connect-tab[data-tab="paste"]',
                    title: 'nostrconnect:// Method',
                    text: 'If the app gives you a nostrconnect:// URI, paste it here. This is common when scanning QR codes.',
                    position: 'bottom',
                    waitFor: '#connect-modal[style*="flex"]'
                }
            ]
        },
        'grant-access': {
            id: 'grant-access',
            name: 'Granting Access',
            description: 'Allow other users or signers to use your key',
            page: '/keys',
            steps: [
                {
                    target: '.grant-btn',
                    title: 'Grant Access',
                    text: 'Click this to allow another pubkey to sign as this identity. Use for team members, proxy signers, or automated tools.',
                    position: 'bottom'
                },
                {
                    target: '#grant-user-pubkey',
                    title: 'Enter the Pubkey',
                    text: 'Enter the npub or hex pubkey of who you\'re granting access to. For proxy signers, this is the pubkey shown after creating the proxy.',
                    position: 'bottom',
                    waitFor: '#grant-modal[style*="flex"]'
                },
                {
                    target: 'input[name="access_level"][value="custom"]',
                    title: 'Custom Permissions',
                    text: 'Optionally restrict what they can do. For example, allow signing notes (kind 1) but not DMs (kind 4).',
                    position: 'right',
                    waitFor: '#grant-modal[style*="flex"]'
                }
            ]
        }
    };

    // Help tooltip content for info icons
    const TOOLTIPS = {
        'proxy-key': 'A proxy key forwards signing requests to another signer instead of signing locally. Use this to chain signers together without exposing private keys.',
        'approval-toggle': 'When enabled, each signing request must be manually approved. When disabled, requests are auto-approved for connected apps.',
        'grant-access': 'Allow another user or signer to sign events using this key. Useful for team accounts or proxy signer setups.',
        'bunker-uri': 'A connection string that apps use to connect to your signer. Contains your public key and the relay addresses where the signer listens.',
        'nostrconnect-uri': 'A connection string from an app. When an app shows you a QR code or URI starting with nostrconnect://, paste it here.',
        'custom-relays': 'Override the default relays for this key. The signer will listen on these relays instead of the globally configured ones.',
        'frost-threshold': 'The number of shares required to sign. A 2-of-3 threshold means any 2 share holders can sign together.',
        'frost-participants': 'Other signers who will hold shares of this FROST key. They participate in key generation via encrypted Nostr DMs.',
        'encryption-method': 'How your private key is encrypted at rest. "local" uses the server\'s encryption key. "vault" uses per-user HashiCorp Vault transit keys for stronger isolation.',
        'connect-to-app': 'Two ways to connect: (1) Copy bunker:// from here and paste into the app, or (2) Copy nostrconnect:// from the app and paste here.'
    };

    // Initialize Shepherd tour
    function createTour(tutorialId) {
        const tutorial = TUTORIALS[tutorialId];
        if (!tutorial) {
            console.error('Tutorial not found:', tutorialId);
            return null;
        }

        // Check if we're on the right page
        if (tutorial.page && !window.location.pathname.startsWith(tutorial.page)) {
            if (confirm(`This tutorial is for the ${tutorial.page} page. Go there now?`)) {
                sessionStorage.setItem('pendingTutorial', tutorialId);
                window.location.href = tutorial.page;
            }
            return null;
        }

        const tour = new Shepherd.Tour({
            useModalOverlay: true,
            defaultStepOptions: {
                cancelIcon: { enabled: true },
                scrollTo: { behavior: 'smooth', block: 'center' },
                classes: 'shepherd-theme-custom'
            }
        });

        tutorial.steps.forEach((step, index) => {
            const isLast = index === tutorial.steps.length - 1;
            const buttons = [];

            if (index > 0) {
                buttons.push({
                    text: 'Back',
                    action: tour.back,
                    classes: 'shepherd-button'
                });
            }

            buttons.push({
                text: isLast ? 'Finish' : 'Next',
                action: isLast ? tour.complete : tour.next,
                classes: 'shepherd-button shepherd-button-primary'
            });

            const stepConfig = {
                id: `step-${index}`,
                title: step.title,
                text: step.text,
                buttons: buttons
            };

            // Only attach to element if it exists
            if (step.target) {
                const targetEl = document.querySelector(step.target);
                if (targetEl) {
                    stepConfig.attachTo = {
                        element: step.target,
                        on: step.position || 'bottom'
                    };
                }
            }

            // Handle waitFor conditions
            if (step.waitFor) {
                stepConfig.beforeShowPromise = () => {
                    return new Promise((resolve) => {
                        const checkElement = () => {
                            const el = document.querySelector(step.waitFor);
                            if (el && el.offsetParent !== null) {
                                resolve();
                            } else {
                                setTimeout(checkElement, 100);
                            }
                        };
                        checkElement();
                    });
                };
            }

            tour.addStep(stepConfig);
        });

        return tour;
    }

    // Start a tutorial
    function startTutorial(tutorialId) {
        const tour = createTour(tutorialId);
        if (tour) {
            tour.start();
        }
    }

    // Create help button and menu
    function createHelpUI() {
        // Don't show on login/register pages
        if (window.location.pathname === '/login' || window.location.pathname === '/register' || window.location.pathname === '/') {
            return;
        }

        // Help button
        const helpBtn = document.createElement('button');
        helpBtn.className = 'help-btn';
        helpBtn.setAttribute('aria-label', 'Help and tutorials');
        helpBtn.setAttribute('title', 'Help and tutorials');

        // Help menu
        const helpMenu = document.createElement('div');
        helpMenu.className = 'help-menu';
        helpMenu.id = 'help-menu';

        // Determine which tutorials are relevant to current page
        const currentPath = window.location.pathname;
        const relevantTutorials = Object.values(TUTORIALS).filter(t =>
            t.page === currentPath || !t.page
        );

        if (relevantTutorials.length > 0) {
            relevantTutorials.forEach(tutorial => {
                const item = document.createElement('button');
                item.className = 'help-menu-item';
                item.textContent = tutorial.name;
                item.addEventListener('click', () => {
                    helpMenu.classList.remove('visible');
                    startTutorial(tutorial.id);
                });
                helpMenu.appendChild(item);
            });

            // Divider
            const divider = document.createElement('div');
            divider.className = 'help-menu-divider';
            helpMenu.appendChild(divider);
        }

        // All tutorials option
        const allTutorials = document.createElement('button');
        allTutorials.className = 'help-menu-item';
        allTutorials.textContent = 'All Tutorials';
        allTutorials.addEventListener('click', () => {
            helpMenu.classList.remove('visible');
            showAllTutorials();
        });
        helpMenu.appendChild(allTutorials);

        // Toggle menu
        helpBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            helpMenu.classList.toggle('visible');
        });

        // Close menu on outside click
        document.addEventListener('click', () => {
            helpMenu.classList.remove('visible');
        });

        document.body.appendChild(helpBtn);
        document.body.appendChild(helpMenu);
    }

    // Show all tutorials in a modal
    function showAllTutorials() {
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.style.display = 'flex';

        const content = document.createElement('div');
        content.className = 'modal-content modal-lg';
        content.innerHTML = `
            <h2>Tutorials</h2>
            <p class="text-muted" style="margin-bottom: 1rem;">Learn how to use Cloistr Signer</p>
            <div id="tutorial-list"></div>
            <div class="modal-actions">
                <button type="button" class="btn btn-secondary" id="close-tutorials">Close</button>
            </div>
        `;

        const list = content.querySelector('#tutorial-list');
        Object.values(TUTORIALS).forEach(tutorial => {
            const item = document.createElement('button');
            item.className = 'help-menu-item';
            item.style.cssText = 'display: block; width: 100%; margin-bottom: 0.5rem;';
            item.innerHTML = `<strong>${tutorial.name}</strong><br><small class="text-muted">${tutorial.description}</small>`;
            item.addEventListener('click', () => {
                modal.remove();
                startTutorial(tutorial.id);
            });
            list.appendChild(item);
        });

        content.querySelector('#close-tutorials').addEventListener('click', () => modal.remove());
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.remove();
        });

        modal.appendChild(content);
        document.body.appendChild(modal);
    }

    // Initialize tooltips for info icons
    function initTooltips() {
        document.querySelectorAll('[data-tooltip]').forEach(el => {
            const tooltipId = el.getAttribute('data-tooltip');
            const tooltipText = TOOLTIPS[tooltipId];
            if (tooltipText) {
                const wrapper = document.createElement('span');
                wrapper.className = 'has-tooltip';

                const icon = document.createElement('span');
                icon.className = 'info-icon';
                icon.setAttribute('tabindex', '0');
                icon.setAttribute('aria-label', 'More information');

                const tooltip = document.createElement('span');
                tooltip.className = 'tooltip';
                tooltip.textContent = tooltipText;

                el.parentNode.insertBefore(wrapper, el);
                wrapper.appendChild(el);
                wrapper.appendChild(icon);
                wrapper.appendChild(tooltip);
            }
        });
    }

    // Check for pending tutorial from page navigation
    function checkPendingTutorial() {
        const pending = sessionStorage.getItem('pendingTutorial');
        if (pending) {
            sessionStorage.removeItem('pendingTutorial');
            setTimeout(() => startTutorial(pending), 500);
        }
    }

    // Export for use in other scripts
    window.CloistrTutorials = {
        TUTORIALS,
        TOOLTIPS,
        startTutorial,
        createTour
    };

    // Initialize on DOM ready
    document.addEventListener('DOMContentLoaded', () => {
        createHelpUI();
        initTooltips();
        checkPendingTutorial();
    });
})();
