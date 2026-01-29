import type { XboxDisplayClaims } from './xbox-display-claims.js';

export type { XboxDisplayClaims } from './xbox-display-claims.js';

/**
 * Represents an Xbox authentication ticket (token response).
 */
export interface XboxTicket {
  /**
   * When the token was issued (ISO 8601 timestamp).
   */
  IssueInstant?: string;

  /**
   * When the token expires (ISO 8601 timestamp).
   */
  NotAfter?: string;

  /**
   * The actual token value.
   */
  Token?: string;

  /**
   * Claims associated with the token.
   */
  DisplayClaims?: XboxDisplayClaims;
}

/**
 * Type guard to check if an XboxTicket has a valid token.
 */
export function hasToken(ticket: XboxTicket | null | undefined): ticket is XboxTicket & { Token: string } {
  return ticket !== null && ticket !== undefined && typeof ticket.Token === 'string' && ticket.Token.length > 0;
}

/**
 * Extracts the user hash from an Xbox ticket's display claims.
 * @param ticket - The Xbox ticket to extract from.
 * @returns The user hash, or undefined if not present.
 */
export function getUserHash(ticket: XboxTicket | null | undefined): string | undefined {
  return ticket?.DisplayClaims?.xui?.[0]?.uhs;
}
