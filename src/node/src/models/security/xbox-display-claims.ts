/**
 * User identity claims from Xbox Live.
 */
export interface XboxXui {
  /**
   * User hash (used in XBL3.0 authorization header).
   */
  uhs?: string;

  /**
   * Xbox User ID (XUID).
   */
  xid?: string;

  /**
   * Gamertag (display name).
   */
  gtg?: string;

  /**
   * Age group.
   */
  agg?: string;

  /**
   * User settings restrictions.
   */
  usr?: string;

  /**
   * User title restrictions.
   */
  utr?: string;

  /**
   * Privileges string.
   */
  prv?: string;

  /**
   * Modern gamertag.
   */
  mgt?: string;

  /**
   * Unique modern gamertag (with discriminator).
   */
  umg?: string;
}

/**
 * Device identity claims from Xbox Live.
 */
export interface XboxXdi {
  /**
   * Device ID.
   */
  did?: string;

  /**
   * Device clock skew.
   */
  dcs?: string;
}

/**
 * Title (application/game) identity claims from Xbox Live.
 */
export interface XboxXti {
  /**
   * Title ID.
   */
  tid?: string;
}

/**
 * Container for display claims returned in Xbox tickets.
 */
export interface XboxDisplayClaims {
  /**
   * User identity claims. May be a single object or array.
   */
  xui?: XboxXui[];

  /**
   * Device identity claims.
   */
  xdi?: XboxXdi;

  /**
   * Title identity claims.
   */
  xti?: XboxXti;
}
