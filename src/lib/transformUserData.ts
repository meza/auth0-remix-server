import camelize from 'camelize-ts';
import type { Auth0UserProfile, UserProfile } from '../Auth0RemixTypes.js';

export const transformUserData = (data: Auth0UserProfile) =>
  camelize(data) satisfies UserProfile;
