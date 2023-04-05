export const mergeHeaders = (...sources: HeadersInit[]): Headers => {
  const result: Headers = new Headers();

  for (const source of sources) {
    const headers: Headers = new Headers(source);

    for (const [key, value] of headers.entries()) {
      result.append(key, value);
    }
  }

  return result;
};
