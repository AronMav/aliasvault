import { describe, it, expect } from 'vitest';

import {
  ARGON2ID_DEGREE_OF_PARALLELISM,
  ARGON2ID_ITERATIONS,
  ARGON2ID_MEMORY_SIZE,
  ENCRYPTION_SETTINGS,
  ENCRYPTION_TYPE,
} from '../EncryptionDefaults';

describe('EncryptionDefaults', () => {
  it('names the only algorithm the clients implement', () => {
    expect(ENCRYPTION_TYPE).toBe('Argon2Id');
  });

  /**
   * The string, not the numbers, is what registration stores against the vault and what every
   * client compares, so key order is part of the value.
   */
  it('serialises the settings in the canonical key order', () => {
    expect(Object.keys(JSON.parse(ENCRYPTION_SETTINGS))).toEqual([
      'DegreeOfParallelism',
      'MemorySize',
      'Iterations',
    ]);
  });

  it('builds the settings from the same constants it exports', () => {
    const parsed = JSON.parse(ENCRYPTION_SETTINGS);
    expect(parsed.DegreeOfParallelism).toBe(ARGON2ID_DEGREE_OF_PARALLELISM);
    expect(parsed.MemorySize).toBe(ARGON2ID_MEMORY_SIZE);
    expect(parsed.Iterations).toBe(ARGON2ID_ITERATIONS);
  });
});
