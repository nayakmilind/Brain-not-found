import { ApiError } from "../../../api/errors";

type ApiErrorNoticeProps = {
  error: unknown;
  fallback: string;
};

export function ApiErrorNotice({ error, fallback }: ApiErrorNoticeProps) {
  if (!error) {
    return null;
  }
  const message = error instanceof ApiError ? error.message : fallback;
  const requestId = error instanceof ApiError ? error.requestId : null;

  return (
    <div className="error-banner" role="alert">
      <span className="error-icon" aria-hidden="true">
        !
      </span>
      <span>
        {message}
        {requestId && <small>Reference: {requestId}</small>}
      </span>
    </div>
  );
}
