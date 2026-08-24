/**
 * Toggle — a styled boolean switch for feature settings.
 *
 * NOTE: @cloistr/ui v0.20.x ships no shared Toggle/Switch component.
 * This is a local implementation. Styles live in styles/index.css under
 * "Local Toggle Component". Follow-up: replace when @cloistr/ui ships one.
 *
 * Usage:
 *   <Toggle
 *     id="disposable-mode"
 *     checked={keyData.disposable_mode}
 *     onChange={(v) => mutation.mutate(v)}
 *     disabled={mutation.isPending}
 *     label="Disposable mode"
 *   />
 */

import { useId } from 'react';

export interface ToggleProps {
  /** Controlled state */
  checked: boolean;
  /** Called with the NEW value when the user clicks */
  onChange: (value: boolean) => void;
  /** Disables interaction and applies reduced opacity */
  disabled?: boolean;
  /** Text label rendered to the right of the track */
  label?: string;
  /** Optional id; auto-generated if omitted */
  id?: string;
  className?: string;
}

export function Toggle({ checked, onChange, disabled = false, label, id, className }: ToggleProps) {
  const autoId = useId();
  const inputId = id ?? autoId;

  return (
    <label
      htmlFor={inputId}
      className={`toggle-root${className ? ` ${className}` : ''}`}
      data-disabled={disabled ? 'true' : 'false'}
    >
      <div
        className="toggle-track"
        data-checked={checked ? 'true' : 'false'}
      >
        <input
          id={inputId}
          type="checkbox"
          role="switch"
          aria-checked={checked}
          className="toggle-input"
          checked={checked}
          disabled={disabled}
          onChange={(e) => onChange(e.target.checked)}
        />
        <div className="toggle-thumb" />
      </div>
      {label && <span className="toggle-label">{label}</span>}
    </label>
  );
}
