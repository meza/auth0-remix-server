import type { Auth0UserProfile, UserProfile } from '../Auth0RemixTypes.js';

export const transformUserData = (data: Auth0UserProfile): UserProfile => {
  /* eslint-disable security/detect-object-injection */
  const renameKeys = (obj: {[key: string]: string | boolean | number | object}) => {
    const keys = Object.keys(obj);
    keys.forEach(key => {
      const newKey = key.replace(/_(\w)/g, (_match, p1) => p1.toUpperCase());
      if (newKey !== key) {
        obj[newKey] = obj[key];
        delete obj[key];
      }
      if (typeof obj[newKey] === 'object') {
        renameKeys(obj[newKey] as {[key: string]: string | boolean | number | object});
      }
    });
  };
  renameKeys(data);

  return structuredClone(data) as unknown as UserProfile;
};
