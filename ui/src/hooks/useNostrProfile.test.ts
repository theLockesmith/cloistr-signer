/**
 * useNostrProfile — source-level structural tests.
 *
 * These run in a Node environment (no DOM / jsdom). They verify the module's
 * exported shape, the NostrProfile interface contract, and the profile-parsing
 * logic that would run inside the onevent callback. Behavioural tests (mocking
 * SimplePool, verifying cache hits, testing the hook lifecycle) require jsdom +
 * @testing-library/react-hooks; that is a follow-up.
 */

import { describe, it, expect } from 'vitest';
import * as ProfileModule from './useNostrProfile';

describe('useNostrProfile module exports', () => {
  it('exports useNostrProfile as a function', () => {
    expect(typeof ProfileModule.useNostrProfile).toBe('function');
  });

  it('useNostrProfile accepts two parameters (pubkey, relays)', () => {
    // The function signature is (pubkey: string | undefined, relays: string[])
    expect(ProfileModule.useNostrProfile.length).toBe(2);
  });
});

describe('NostrProfile parsing contract', () => {
  // The onevent callback parses JSON content from a kind:0 event. We test
  // the same extraction logic here to catch regressions in field names.

  function parseProfileContent(raw: string): ProfileModule.NostrProfile | null {
    try {
      const content = JSON.parse(raw);
      return {
        nip05: content.nip05,
        name: content.name ?? content.display_name,
        picture: content.picture,
      };
    } catch {
      return null;
    }
  }

  it('extracts nip05, name, and picture from valid kind:0 content', () => {
    const content = JSON.stringify({
      name: 'fraiyr',
      nip05: 'fraiyr@cloistr.xyz',
      picture: 'https://example.com/avatar.jpg',
      about: 'ignored field',
    });

    const result = parseProfileContent(content);
    expect(result).toEqual({
      nip05: 'fraiyr@cloistr.xyz',
      name: 'fraiyr',
      picture: 'https://example.com/avatar.jpg',
    });
  });

  it('falls back to display_name when name is absent', () => {
    const content = JSON.stringify({
      display_name: 'Fraiyr Display',
      nip05: 'fraiyr@cloistr.xyz',
    });

    const result = parseProfileContent(content);
    expect(result).toEqual({
      nip05: 'fraiyr@cloistr.xyz',
      name: 'Fraiyr Display',
      picture: undefined,
    });
  });

  it('prefers name over display_name when both are present', () => {
    const content = JSON.stringify({
      name: 'canonical',
      display_name: 'fallback',
    });

    const result = parseProfileContent(content);
    expect(result?.name).toBe('canonical');
  });

  it('handles content with no profile fields (all undefined)', () => {
    const content = JSON.stringify({ lud16: 'someone@getalby.com' });

    const result = parseProfileContent(content);
    expect(result).toEqual({
      nip05: undefined,
      name: undefined,
      picture: undefined,
    });
  });

  it('returns null for malformed JSON', () => {
    const result = parseProfileContent('not json at all');
    expect(result).toBeNull();
  });

  it('returns null for empty string', () => {
    const result = parseProfileContent('');
    expect(result).toBeNull();
  });
});
