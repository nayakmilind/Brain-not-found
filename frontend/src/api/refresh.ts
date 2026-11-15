export type RefreshCoordinator<T> = () => Promise<T | null>;

export function createRefreshCoordinator<T>(
  refresh: () => Promise<T | null>,
): RefreshCoordinator<T> {
  let inFlight: Promise<T | null> | null = null;

  return () => {
    if (inFlight) {
      return inFlight;
    }
    inFlight = refresh().finally(() => {
      inFlight = null;
    });
    return inFlight;
  };
}
