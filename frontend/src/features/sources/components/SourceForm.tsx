import { useMutation } from "@tanstack/react-query";
import { useRef, useState, type FormEvent } from "react";
import { ApiError } from "../../../api/errors";
import {
  createTextSource,
  createUrlSource,
  uploadSourceFile,
  type SourceFileExtension,
  type SourceFileKind,
  type SourceKind,
} from "../api";
import { ApiErrorNotice } from "./ApiErrorNotice";

type SourceFormProps = {
  onCreated: () => void;
  onConsentRequired: () => void;
};

type FormMode = "url" | "text" | "file";

type CreateSourceInput =
  | { mode: "url"; label: string; uri: string }
  | { mode: "text"; label: string; content: string; kind: SourceKind }
  | {
      mode: "file";
      file: File;
      label: string;
      extension: SourceFileExtension;
      kind: SourceFileKind;
    };

const maximumSourceBytes = 5_242_880;

function sourceExtension(fileName: string): SourceFileExtension | null {
  const extension = fileName.toLowerCase().split(".").pop();
  return extension === "txt" || extension === "pdf" || extension === "docx"
    ? extension
    : null;
}

export function SourceForm({ onCreated, onConsentRequired }: SourceFormProps) {
  const [mode, setMode] = useState<FormMode>("url");
  const [label, setLabel] = useState("");
  const [uri, setUri] = useState("");
  const [content, setContent] = useState("");
  const [sourceKind, setSourceKind] = useState<SourceKind>("TEXT");
  const [fileKind, setFileKind] = useState<SourceFileKind>("FILE");
  const [file, setFile] = useState<File | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const createMutation = useMutation({
    mutationFn: async (input: CreateSourceInput) => {
      if (input.mode === "url") {
        return createUrlSource(input.label, input.uri);
      }
      if (input.mode === "text") {
        return createTextSource(input.kind, input.label, input.content);
      }
      return uploadSourceFile(input.file, input.label, input.extension, input.kind);
    },
    onSuccess: () => {
      setLabel("");
      setUri("");
      setContent("");
      setFile(null);
      if (fileInput.current) {
        fileInput.current.value = "";
      }
      onCreated();
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 403) {
        onConsentRequired();
      }
    },
  });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    const trimmedLabel = label.trim();
    if (!trimmedLabel || trimmedLabel.length > 120) {
      setFormError("Add a label between 1 and 120 characters.");
      return;
    }

    if (mode === "url") {
      try {
        const parsedUrl = new URL(uri);
        if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
          setFormError("Use a public HTTP or HTTPS website URL.");
          return;
        }
      } catch {
        setFormError("Enter a complete HTTP or HTTPS website URL.");
        return;
      }
      createMutation.mutate({ mode, label: trimmedLabel, uri: uri.trim() });
      return;
    }

    if (mode === "text") {
      if (!content.trim()) {
        setFormError("Paste the text you want to assess.");
        return;
      }
      createMutation.mutate({
        mode,
        label: trimmedLabel,
        content,
        kind: sourceKind,
      });
      return;
    }

    if (!file) {
      setFormError("Choose a TXT, PDF, or DOCX file to upload.");
      return;
    }
    const extension = sourceExtension(file.name);
    if (!extension) {
      setFormError("This file type is not supported. Choose TXT, PDF, or DOCX.");
      return;
    }
    if (file.size > maximumSourceBytes) {
      setFormError("Files must be 5 MB or smaller.");
      return;
    }
    createMutation.mutate({
      mode,
      file,
      label: trimmedLabel,
      extension,
      kind: fileKind,
    });
  }

  const tabs: { value: FormMode; label: string }[] = [
    { value: "url", label: "Website URL" },
    { value: "text", label: "Pasted text" },
    { value: "file", label: "File export" },
  ];

  return (
    <section className="source-form-card" aria-labelledby="add-source-title">
      <div className="source-form-heading">
        <p className="eyebrow">YOUR SOURCES</p>
        <h2 id="add-source-title">Add a source you own</h2>
        <p>
          We never ask for platform credentials. Pasted text and uploaded files are
          self-declared and are never fetched.
        </p>
      </div>

      <div className="source-tabs" role="group" aria-label="Source type">
        {tabs.map((tab) => (
          <button
            key={tab.value}
            aria-pressed={mode === tab.value}
            className={mode === tab.value ? "source-tab source-tab-active" : "source-tab"}
            onClick={() => {
              setMode(tab.value);
              setFormError(null);
              createMutation.reset();
            }}
            type="button"
          >
            {tab.label}
          </button>
        ))}
      </div>

      <form id="source-form-panel" className="source-form" noValidate onSubmit={submit}>
        <label className="source-field">
          <span>Source label</span>
          <input
            autoComplete="off"
            maxLength={120}
            onChange={(event) => setLabel(event.currentTarget.value)}
            placeholder="A label only you will recognize"
            required
            value={label}
          />
        </label>

        {mode === "url" && (
          <>
            <label className="source-field">
              <span>Website URL</span>
              <input
                autoComplete="url"
                onChange={(event) => setUri(event.currentTarget.value)}
                placeholder="https://example.com/your-profile"
                required
                type="url"
                value={uri}
              />
            </label>
            <p className="source-field-note">
              Adding a URL does not fetch it. Verify ownership first; only then can a scan
              request access it.
            </p>
          </>
        )}

        {mode === "text" && (
          <>
            <label className="source-field">
              <span>What are you adding?</span>
              <select
                onChange={(event) => {
                  const value = event.currentTarget.value;
                  if (value === "TEXT" || value === "PLATFORM_EXPORT") {
                    setSourceKind(value);
                  }
                }}
                value={sourceKind}
              >
                <option value="TEXT">Pasted text</option>
                <option value="PLATFORM_EXPORT">Text from my platform export</option>
              </select>
            </label>
            <label className="source-field">
              <span>Text to assess</span>
              <textarea
                maxLength={5_242_880}
                onChange={(event) => setContent(event.currentTarget.value)}
                placeholder="Paste content from a source you own."
                required
                rows={7}
                value={content}
              />
            </label>
            <p className="source-field-note">
              This content is not fetched. Avoid passwords or other secrets.
            </p>
          </>
        )}

        {mode === "file" && (
          <>
            <label className="source-field">
              <span>Upload type</span>
              <select
                onChange={(event) => {
                  const value = event.currentTarget.value;
                  if (value === "FILE" || value === "PLATFORM_EXPORT") {
                    setFileKind(value);
                  }
                }}
                value={fileKind}
              >
                <option value="FILE">Personal file</option>
                <option value="PLATFORM_EXPORT">Platform export</option>
              </select>
            </label>
            <label className="source-field">
              <span>Choose a file</span>
              <input
                accept=".txt,.pdf,.docx,text/plain,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                onChange={(event) => setFile(event.currentTarget.files?.[0] ?? null)}
                ref={fileInput}
                required
                type="file"
              />
            </label>
            <p className="source-field-note">
              TXT, PDF, or DOCX; maximum 5 MB. Files are uploaded directly and are never
              fetched from a website.
            </p>
          </>
        )}

        {formError && (
          <div className="inline-form-error" role="alert">
            {formError}
          </div>
        )}
        <ApiErrorNotice
          error={createMutation.error}
          fallback="The source could not be added. Check your connection and try again."
        />
        {createMutation.isSuccess && (
          <p className="success-message" role="status">
            Source added. The server stores only a masked label preview in the source
            list.
          </p>
        )}

        <button
          className="primary-button source-submit"
          disabled={createMutation.isPending}
          type="submit"
        >
          {createMutation.isPending ? "Adding source…" : "Add source"}
          <span aria-hidden="true">→</span>
        </button>
      </form>
    </section>
  );
}
