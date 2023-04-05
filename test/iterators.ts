type IterableToObject<T> = T extends Iterable<readonly [PropertyKey, infer S]>
  ? Record<PropertyKey, S | S[]>
  : never;

type IterableToMap<T> = T extends Iterable<readonly [PropertyKey, infer S]>
  ? Map<PropertyKey, S | S[]>
  : never;

export const iterableToObject = <T extends Iterable<readonly [PropertyKey, unknown]>>(
  it: T
) => {
  const o = new Map() as IterableToMap<T>;
  for (const [k, v] of it) {
    if (o.has(k)) {
      const existingVal = o.get(k);
      o.set(k, Array.isArray(existingVal) ? [...existingVal, v] : [existingVal, v]);
    } else {
      o.set(k, v);
    }
  }
  return Object.fromEntries(o.entries()) as IterableToObject<T>;
};
