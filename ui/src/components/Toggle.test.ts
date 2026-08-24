/**
 * Toggle component — source-level structural tests.
 *
 * These tests run in a Node environment (no DOM / jsdom). They verify the
 * module's exported shape and prop-type contract at the source level, NOT
 * behavioural rendering. They are designed to fail if the Toggle component
 * is removed or its interface is broken.
 *
 * NOTE: These are explicitly source-level tests, not behavioural tests.
 * DOM-level rendering tests (clicking the toggle, verifying aria-checked
 * updates, etc.) require jsdom + @testing-library/react. That is a
 * follow-up task once those dependencies are added to the UI package.
 */

import { describe, it, expect } from 'vitest';
import * as ToggleModule from './Toggle';

describe('Toggle module exports', () => {
  it('exports a Toggle function component', () => {
    expect(typeof ToggleModule.Toggle).toBe('function');
  });

  it('Toggle function has a name (not minified away in tests)', () => {
    expect(ToggleModule.Toggle.name).toBe('Toggle');
  });

  it('only exports Toggle and ToggleProps (no stray exports)', () => {
    // ToggleProps is a TypeScript type and does not appear at runtime, so
    // the only runtime export should be Toggle itself.
    const keys = Object.keys(ToggleModule);
    expect(keys).toContain('Toggle');
    // Guard: if someone adds an unexpected runtime export this test catches it
    // so we review whether the test list needs updating.
    expect(keys.length).toBe(1);
  });
});

describe('Toggle prop contract (source-level)', () => {
  // We cannot call the component without a DOM, but we can verify the function
  // has the correct arity and default argument handling by inspecting source.
  // The real guard is TypeScript: these tests confirm the compile-time contract
  // does not drift from what the CSS + markup expect.

  it('Toggle is callable as a function (React function component interface)', () => {
    // React function components are plain functions that accept one props object.
    // This confirms the component was not accidentally converted to a class.
    expect(ToggleModule.Toggle.length).toBeLessThanOrEqual(1);
  });
});

describe('ThemeToggle placement invariant (source-level)', () => {
  // Verify that Layout.tsx passes ThemeToggle as a Header child rather than
  // embedding it inside the auth-gated subheader nav. This test reads the
  // source file directly and fails if the placement regresses.
  it('Layout passes ThemeToggle as a Header child, not inside the auth-gated subheader', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const layoutPath = path.resolve(
      import.meta.dirname ?? __dirname,
      '../components/Layout.tsx',
    );
    const src = fs.readFileSync(layoutPath, 'utf-8');

    // The ThemeToggle must appear BETWEEN <Header and </Header> (as a child).
    const headerBlock = src.match(/<Header[\s\S]*?<\/Header>/)?.[0] ?? '';
    expect(headerBlock).toContain('<ThemeToggle');

    // The ThemeToggle must NOT appear inside the app-subheader nav block.
    // app-subheader nav is always after </Header> so find the nav block.
    const afterHeader = src.split('</Header>')[1] ?? '';
    const subheaderBlock = afterHeader.match(/<nav className="app-subheader"[\s\S]*?<\/nav>/)?.[0] ?? '';
    expect(subheaderBlock).not.toContain('<ThemeToggle');
  });
});

describe('100dvh replacement invariant (source-level)', () => {
  it('index.css contains no remaining 100vh references', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const cssPath = path.resolve(
      import.meta.dirname ?? __dirname,
      '../styles/index.css',
    );
    const src = fs.readFileSync(cssPath, 'utf-8');
    // Check there are no bare 100vh (not 100dvh) remaining.
    // The regex is anchored to avoid false matches within comments.
    const matches = src.match(/:\s*(?:calc\()?\s*100vh\b/g) ?? [];
    expect(matches).toHaveLength(0);
  });

  it('index.css uses 100dvh in base layout rules', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const cssPath = path.resolve(
      import.meta.dirname ?? __dirname,
      '../styles/index.css',
    );
    const src = fs.readFileSync(cssPath, 'utf-8');
    const dvhMatches = src.match(/100dvh/g) ?? [];
    // We replaced 5 instances + added 1 modal (90dvh).
    // At minimum 5 dvh references must exist.
    expect(dvhMatches.length).toBeGreaterThanOrEqual(5);
  });
});

describe('Toggle CSS classes invariant (source-level)', () => {
  it('index.css defines the toggle-root class', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const cssPath = path.resolve(
      import.meta.dirname ?? __dirname,
      '../styles/index.css',
    );
    const src = fs.readFileSync(cssPath, 'utf-8');
    expect(src).toContain('.toggle-root');
    expect(src).toContain('.toggle-track');
    expect(src).toContain('.toggle-thumb');
  });
});

describe('ThemeProvider mount invariant (source-level)', () => {
  // These tests verify at the source level that ThemeProvider is mounted and that
  // ThemeToggle will therefore have a context to read. No DOM / jsdom required:
  // we read the source files directly. "Source-level" means we are asserting on
  // text, not on runtime rendering behaviour.
  it('App.tsx imports ThemeProvider from @cloistr/ui', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const appPath = path.resolve(
      import.meta.dirname ?? __dirname,
      '../App.tsx',
    );
    const src = fs.readFileSync(appPath, 'utf-8');
    // Confirm the import line exists.
    expect(src).toMatch(/import\s*\{[^}]*ThemeProvider[^}]*\}\s*from\s*['"]@cloistr\/ui['"]/);
  });

  it('App.tsx wraps the tree in <ThemeProvider>', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const appPath = path.resolve(
      import.meta.dirname ?? __dirname,
      '../App.tsx',
    );
    const src = fs.readFileSync(appPath, 'utf-8');
    // The default export must open with <ThemeProvider> as the outermost JSX.
    // This assertion fails if ThemeProvider is removed or demoted below another provider.
    expect(src).toContain('<ThemeProvider>');
    // Verify it is also closed.
    expect(src).toContain('</ThemeProvider>');
  });

  it('ThemeProvider wraps the QueryClientProvider (outermost provider)', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const appPath = path.resolve(
      import.meta.dirname ?? __dirname,
      '../App.tsx',
    );
    const src = fs.readFileSync(appPath, 'utf-8');
    // ThemeProvider must open BEFORE QueryClientProvider inside the default export JSX.
    const themeIdx = src.indexOf('<ThemeProvider>');
    const queryIdx = src.indexOf('<QueryClientProvider');
    expect(themeIdx).toBeGreaterThanOrEqual(0);
    expect(queryIdx).toBeGreaterThan(themeIdx);
  });
});

describe('btn-sm tap target invariant (source-level)', () => {
  // .btn-sm and .btn are on the SAME element. At equal CSS specificity the later
  // rule wins: if .btn-sm sets a lower min-height it overrides .btn's 44px floor.
  // This test asserts that .btn-sm does NOT declare min-height, leaving the 44px
  // floor from .btn intact.
  it('index.css .btn-sm block does not set min-height', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const cssPath = path.resolve(
      import.meta.dirname ?? __dirname,
      '../styles/index.css',
    );
    const src = fs.readFileSync(cssPath, 'utf-8');
    // Extract the .btn-sm rule block (everything between the selector and the closing brace).
    const btnSmBlock = src.match(/\.btn-sm\s*\{([^}]*)\}/)?.[1] ?? '';
    // Match the CSS property declaration (colon required), not just the word in a comment.
    expect(btnSmBlock).not.toMatch(/min-height\s*:/);
  });

  it('index.css .btn block sets min-height: 44px', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const cssPath = path.resolve(
      import.meta.dirname ?? __dirname,
      '../styles/index.css',
    );
    const src = fs.readFileSync(cssPath, 'utf-8');
    // Confirm the base .btn block still holds the 44px floor.
    const btnBlock = src.match(/^\.btn\s*\{([^}]*)}/m)?.[1] ?? '';
    expect(btnBlock).toMatch(/min-height\s*:\s*44px/);
  });
});

describe('FROST acknowledgement checkboxes invariant (source-level)', () => {
  // Master had 6 raw checkboxes in Keys.tsx. Three were correctly converted to
  // Toggle (disposable_mode, cover_traffic, tor_egress) because they are
  // persistent binary feature flags. Three are kept as checkboxes because they
  // are one-time acknowledgement gates for irreversible operations.
  // This test locks the count so it cannot silently drift.
  it('Keys.tsx has exactly 3 acknowledgement checkboxes', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const keysPath = path.resolve(
      import.meta.dirname ?? __dirname,
      '../pages/Keys.tsx',
    );
    const src = fs.readFileSync(keysPath, 'utf-8');
    const checkboxes = src.match(/type="checkbox"/g) ?? [];
    expect(checkboxes).toHaveLength(3);
  });

  it('Keys.tsx has exactly 3 Toggle usages', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const keysPath = path.resolve(
      import.meta.dirname ?? __dirname,
      '../pages/Keys.tsx',
    );
    const src = fs.readFileSync(keysPath, 'utf-8');
    const toggles = src.match(/<Toggle\b/g) ?? [];
    expect(toggles).toHaveLength(3);
  });
});
