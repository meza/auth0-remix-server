import type { Auth0UserProfile, UserProfile } from '../Auth0RemixTypes.js';

export const transformUserData = async (data: Auth0UserProfile) => {
  const camelize = (await import('camelize-ts')).default;
  return camelize(data) satisfies UserProfile;
};
