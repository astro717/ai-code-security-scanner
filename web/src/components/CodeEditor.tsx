import { useEffect, useRef, useImperativeHandle, forwardRef } from 'react'
import { EditorView, keymap, lineNumbers, highlightActiveLine, Decoration, type DecorationSet } from '@codemirror/view'
import { EditorState, StateField, StateEffect } from '@codemirror/state'
import { javascript } from '@codemirror/lang-javascript'
import { oneDark } from '@codemirror/theme-one-dark'
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands'
import { indentOnInput, bracketMatching } from '@codemirror/language'
import { highlightSelectionMatches } from '@codemirror/search'

// ── Line highlight StateField ─────────────────────────────────────────────────

/** Effect: set the 1-based line number to highlight, or null to clear. */
const setHighlightLine = StateEffect.define<number | null>()

/** Mark decoration applied to the target line's range. */
const highlightLineMark = Decoration.line({ class: 'cm-highlighted-line' })

/** StateField that tracks which line (if any) is decorated. */
const highlightLineField = StateField.define<DecorationSet>({
  create() {
    return Decoration.none
  },
  update(decorations, tr) {
    for (const effect of tr.effects) {
      if (effect.is(setHighlightLine)) {
        if (effect.value === null) return Decoration.none
        const lineNum = effect.value
        if (lineNum < 1 || lineNum > tr.state.doc.lines) return Decoration.none
        const line = tr.state.doc.line(lineNum)
        return Decoration.set([highlightLineMark.range(line.from)])
      }
    }
    // Keep decorations in sync as the document changes
    return decorations.map(tr.changes)
  },
  provide(field) {
    return EditorView.decorations.from(field)
  },
})

export interface CodeEditorHandle {
  scrollToLine: (line: number) => void
}

interface CodeEditorProps {
  value: string
  onChange: (value: string) => void
  onScan: () => void
  isLoading: boolean
}


const editorTheme = EditorView.theme({
  '&': {
    height: '100%',
    minHeight: '400px',
    fontSize: '13px',
    fontFamily: '"JetBrains Mono", "Fira Code", "Cascadia Code", monospace',
    backgroundColor: '#0d1117',
  },
  '.cm-scroller': { overflow: 'auto', fontFamily: 'inherit' },
  '.cm-content': { caretColor: '#e6edf3', padding: '12px 0' },
  '.cm-focused': { outline: 'none' },
  '&.cm-focused .cm-cursor': { borderLeftColor: '#e6edf3' },
  '.cm-gutters': {
    backgroundColor: '#0d1117',
    borderRight: '1px solid #21262d',
    color: '#484f58',
  },
  '.cm-lineNumbers .cm-gutterElement': { minWidth: '2.8em', paddingRight: '8px' },
  '.cm-activeLine': { backgroundColor: 'rgba(255,255,255,0.04)' },
  '.cm-activeLineGutter': { backgroundColor: 'rgba(255,255,255,0.06)' },
  '.cm-highlighted-line': {
    backgroundColor: 'rgba(139, 92, 246, 0.15)',
    outline: '1px solid rgba(139, 92, 246, 0.4)',
  },
})

export const CodeEditor = forwardRef<CodeEditorHandle, CodeEditorProps>(
  function CodeEditor({ value, onChange, onScan, isLoading }, ref) {
    const containerRef = useRef<HTMLDivElement>(null)
    const viewRef = useRef<EditorView | null>(null)
    const onChangeRef = useRef(onChange)
    const onScanRef = useRef(onScan)

    onChangeRef.current = onChange
    onScanRef.current = onScan

    useImperativeHandle(ref, () => ({
      scrollToLine(lineNumber: number) {
        const view = viewRef.current
        if (!view) return
        const doc = view.state.doc
        const clampedLine = Math.max(1, Math.min(lineNumber, doc.lines))
        const line = doc.line(clampedLine)

        // Move cursor to the target line and scroll it into view, then
        // apply the highlight decoration via the StateField.
        view.dispatch({
          selection: { anchor: line.from },
          scrollIntoView: true,
          effects: setHighlightLine.of(clampedLine),
        })

        // Auto-clear the highlight after 2 s.
        setTimeout(() => {
          view.dispatch({ effects: setHighlightLine.of(null) })
        }, 2000)
      },
    }))

    useEffect(() => {
      if (!containerRef.current) return

      const ctrlEnterKeymap = keymap.of([{
        key: 'Ctrl-Enter',
        mac: 'Cmd-Enter',
        run: () => { onScanRef.current(); return true; },
      }])

      const updateListener = EditorView.updateListener.of((update) => {
        if (update.docChanged) {
          onChangeRef.current(update.state.doc.toString())
        }
      })

      const state = EditorState.create({
        doc: value,
        extensions: [
          oneDark,
          editorTheme,
          javascript({ jsx: true, typescript: true }),
          lineNumbers(),
          highlightActiveLine(),
          history(),
          indentOnInput(),
          bracketMatching(),
          highlightSelectionMatches(),
          keymap.of([...defaultKeymap, ...historyKeymap]),
          ctrlEnterKeymap,
          updateListener,
          EditorView.lineWrapping,
          highlightLineField,
        ],
      })

      const view = new EditorView({ state, parent: containerRef.current })
      viewRef.current = view

      return () => {
        view.destroy()
        viewRef.current = null
      }
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    // Sync external value changes (e.g. clear)
    useEffect(() => {
      const view = viewRef.current
      if (!view) return
      const current = view.state.doc.toString()
      if (current !== value) {
        view.dispatch({
          changes: { from: 0, to: current.length, insert: value },
        })
      }
    }, [value])

    return (
      <div className="flex flex-col gap-3 h-full">
        <div
          ref={containerRef}
          className="flex-1 rounded-lg border border-[#1e1e2e] focus-within:border-violet-500/50 transition-colors overflow-hidden"
          style={{ minHeight: '400px' }}
        />

        <button
          onClick={onScan}
          disabled={isLoading || !value.trim()}
          className="flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-violet-600 hover:bg-violet-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-150 font-medium text-sm text-white shadow-lg shadow-violet-900/30"
        >
          {isLoading ? (
            <>
              <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Scanning…
            </>
          ) : (
            <>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              Scan Code
              <span className="text-xs opacity-50 font-mono ml-1">Ctrl+Enter</span>
            </>
          )}
        </button>
      </div>
    )
  },
)
