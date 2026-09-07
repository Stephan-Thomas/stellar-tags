const express = require('express');
const xss = require('xss');
const { StrKey } = require('@stellar/stellar-sdk');
const { prisma, withTransaction } = require('../../../prismaClient');
const { verifyMultiSignerThreshold } = require('../../multisigner-verifier');
const { poolGet, poolRun, poolAll, etagCache } = require('../../db');
const { logger } = require('../../logger');
const { transferAccount } = require('../../services/registrationService');
const { lookupCached, invalidateFederationCache } = require('../../cache');
const {
  paginatedResponse,
  parsePagination,
  parseCursorQuery,
  keysetWhereDesc,
  paginateByKeyset,
  cursorPaginatedResponse,
} = require('../../pagination');
const { asyncHandler } = require('../../middleware/asyncHandler');
const {
  normalizeNameTag,
  validateMemo,
  RESERVED_NAMES,
  RESERVED_USERNAMES,
  MAX_USERNAMES_PER_ADDRESS,
  PRIMARY_USERNAME_ORDER,
  shouldFallbackToLocalRegistry,
} = require('../../utils');
const Filter = require('bad-words');
const profanityFilter = new Filter();
const { verifyFreighterRegistrationSignature } = require('../../services/signatureService');
const { validateSchema } = require('../../middleware/validateSchema');
const { ApiError } = require('../../errors');
const { requireJson } = require('../../middleware/requireJson');
const { authenticateUsernameOwner } = require('../../services/ownershipService');
const {
  ACTIVITY_ACTIONS,
  recordActivity,
  listActivity,
  parseDateRange,
  serializeActivity,
} = require('../../services/activityService');
const {
  registerBodySchema,
  federationQuerySchema,
  lookupQuerySchema,
  usersQuerySchema,
  activityQuerySchema,
} = require('../../schemas');
const { registerUser } = require('../../services/registrationService');
const { lookupUser, listUsers } = require('../../services/userService');


const router = express.Router();

const buildUserSearchWhere = (search) => {
  if (!search) return {};
  return {
    deletedAt: null,
    OR: [
      { username: { contains: search, mode: 'insensitive' } },
      { address: { contains: search, mode: 'insensitive' } },
    ],
  };
};

const serializeUser = (user) => ({
  username: user.username,
  address: user.address,
  created_at: user.createdAt ? user.createdAt.toISOString() : undefined,
});

const getLocalUserByAddress = async (address) =>
  poolGet(
    'SELECT username, address FROM username_registry WHERE address = $1 LIMIT 1',
    [address],
  );

const getLocalUserByUsername = async (username) =>
  poolGet(
    'SELECT username, address FROM username_registry WHERE username = $1 LIMIT 1',
    [username],
  );

const listLocalUsers = async (search, page, limit) => {
  const searchPattern = `%${search}%`;
  const skip = (page - 1) * limit;
  const rows = await poolAll(
    `SELECT username, address, created_at
     FROM username_registry
     WHERE username ILIKE $1 OR address ILIKE $1
     ORDER BY created_at DESC
     LIMIT $2 OFFSET $3`,
    [searchPattern, limit, skip],
  );

  const countRow = await poolGet(
    `SELECT COUNT(*) AS "totalCount"
     FROM username_registry
     WHERE username ILIKE $1 OR address ILIKE $1`,
    [searchPattern],
  );

  const totalCount = Number(countRow?.totalCount || 0);
  return paginatedResponse(
    rows.map((user) => ({
      username: user.username,
      address: user.address,
      created_at: user.created_at,
    })),
    totalCount,
    { page, limit },
  );
};

const registerLocalUser = async ({ username, address }) => {
  const existingByAddress = await getLocalUserByAddress(address);
  if (existingByAddress) {
    const conflictError = new Error('Address already registered');
    conflictError.statusCode = 409;
    throw conflictError;
  }

  const existingByUsername = await getLocalUserByUsername(username);
  if (existingByUsername) {
    const conflictError = new Error('Username is already taken. Please choose another.');
    conflictError.statusCode = 409;
    throw conflictError;
  }

  await poolRun(
    `INSERT INTO username_registry (username, address, created_at)
     VALUES ($1, $2, $3)`,
    [username, address, new Date().toISOString()],
  );
};


/**
 * @openapi
 * /register:
 *   post:
 *     tags:
 *       - v1
 *     description: POST /register
 *     responses:
 *       200:
 *         description: Success
 */
router.post('/register', requireJson, validateSchema({ body: registerBodySchema }), asyncHandler(async (req, res, next) => {
  const safeUsername = xss(req.body.username);
  const username = normalizeNameTag(safeUsername);
  const { address, memo_type: memoType, memo, signature = '', signerAddress = '' } = req.body;

  if (address.toUpperCase().startsWith('S')) {
    return next(
      new ApiError(
        'INVALID_INPUT',
        'Never share your Secret Key. Please register using your Public Key (starts with G).',
      ),
    );
  }

  const usernameLocalPart = username.includes('*') ? username.split('*')[0] : username;

  if (profanityFilter.isProfane(usernameLocalPart)) {
    return next(new ApiError('INVALID_INPUT', 'Username contains restricted words'));
  }

  if (!StrKey.isValidEd25519PublicKey(address)) {
    const error = new Error('Invalid Stellar Public Key format.');
    error.statusCode = 400;
    return next(error);
  }

  const memoError = validateMemo(memoType, memo);
  if (memoError) {
    return next(new ApiError('INVALID_INPUT', memoError));
  }

  const normalizedUsername = username.toLowerCase();
  
  const normalizedLocalPart = normalizedUsername.includes('*') ? normalizedUsername.split('*')[0] : normalizedUsername;
  if (RESERVED_USERNAMES.includes(normalizedLocalPart)) {
    return res.status(403).json({ error: "Username is reserved." });
  }

  if (RESERVED_NAMES.includes(normalizedUsername)) {
    return next(new ApiError('FORBIDDEN', 'This username is reserved and cannot be registered.'));
  }

  try {
    // #613 — an address may carry several usernames (aliases). Registration
    // adds another while the address is under the cap; the first username
    // registered for an address becomes its primary.
    const usernameCount = await prisma.user.count({
      where: { address, deletedAt: null },
    });

    if (usernameCount >= MAX_USERNAMES_PER_ADDRESS) {
      return next(
        new ApiError(
          'CONFLICT',
          `This address already has the maximum of ${MAX_USERNAMES_PER_ADDRESS} federation usernames.`,
        ),
      );
    }
    const isPrimary = usernameCount === 0;

    let verificationResult = null;
    if (signature) {
      const isLegacyPublicKeyFlow =
        StrKey.isValidEd25519PublicKey(signature) && !signerAddress;

      if (isLegacyPublicKeyFlow) {
        verificationResult = await verifyMultiSignerThreshold(address, [signature], {
          operationType: 'management',
        });

        if (!verificationResult.success) {
          const verificationError = new Error(
            verificationResult.errorMessage || 'Signature verification failed'
          );
          verificationError.statusCode = 401;
          throw verificationError;
        }
      } else {
        const claimedSigner = verifyFreighterRegistrationSignature({
          username: req.body.username,
          address: req.body.address,
          signature,
          signerAddress,
        });

        verificationResult = {
          success: true,
          accountId: claimedSigner,
          operationType: 'message',
          requiredThreshold: 1,
          totalWeight: 1,
          signatureCount: 1,
          uniqueSignerCount: 1,
          signatures: [
            {
              publicKey: claimedSigner,
              weight: 1,
              isValid: true,
            },
          ],
          thresholds: {
            low_threshold: 1,
            med_threshold: 1,
            high_threshold: 1,
          },
          signerCount: 1,
          errorMessage: null,
        };
      }
    }

    await prisma.user.create({
      data: {
        username: normalizedUsername,
        address,
        isPrimary,
        ...(memoType && { memoType, memo }),
      },
    });

    await recordActivity(prisma, {
      username: normalizedUsername,
      action: ACTIVITY_ACTIONS.USER_REGISTERED,
      metadata: { address, is_primary: isPrimary, ...(memoType && { memo_type: memoType }) },
      req,
    });

    return res.status(201).json({
      ok: true,
      username: normalizedUsername,
      address,
      is_primary: isPrimary,
      federation_address: `${normalizedUsername}*${process.env.DOMAIN || 'localhost'}`,
      ...(verificationResult && {
        verification: {
          accountId: verificationResult.accountId,
          signerCount: verificationResult.signerCount,
          thresholdMet: verificationResult.success,
          requiredThreshold: verificationResult.requiredThreshold,
          providedWeight: verificationResult.totalWeight,
        },
      }),
      ...(memoType && { memo_type: memoType, memo }),
    });

  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT' || error.code === 'P2002' || (error.message && error.message.includes('UNIQUE'))) {
      return next(new ApiError('CONFLICT', 'Username is already taken. Please choose another.'));
    }
    
    if (error.message && error.message.includes('Account not found')) {
      const notFoundError = new Error(`Account not found on Horizon: ${address}`);
      notFoundError.statusCode = 404;
      return next(notFoundError);
    }

    if (error.statusCode === 401) {
      return next(error);
    }

    return next(error);
  }
}));

router.post('/users/:username/transfer', async (req, res, next) => {
  if (!req.is('application/json')) {
    return res.status(415).json({ error: "Unsupported Media Type. Please send application/json" });
  }

  const { username } = req.params;
  const { oldAddress, newAddress, oldSignature, newSignature } = req.body;

  try {
    const normalizedUsername = typeof username === 'string' ? username.toLowerCase().trim() : '';
    const updatedUser = await transferAccount(
      normalizedUsername,
      oldAddress,
      newAddress,
      oldSignature,
      newSignature
    );

    await recordActivity(prisma, {
      username: updatedUser.username,
      action: ACTIVITY_ACTIONS.USER_TRANSFERRED,
      metadata: { from_address: oldAddress, to_address: updatedUser.address },
      req,
    });

    return res.status(200).json({
      ok: true,
      message: 'Account transferred successfully',
      username: updatedUser.username,
      new_address: updatedUser.address,
    });
  } catch (error) {
    const status = error.statusCode || 500;
    return res.status(status).json({ error: error.message || 'Transfer failed' });
  }
});

router.all('/register', (req, res, next) => next(new ApiError('METHOD_NOT_ALLOWED')));

// #18 — Soft-delete endpoint. Sets deleted_at to now() instead of running a
// hard DELETE so the row is preserved for historical auditing.

/**
 * @openapi
 * /register/:username:
 *   delete:
 *     tags:
 *       - v1
 *     description: DELETE /register/:username
 *     responses:
 *       200:
 *         description: Success
 */
router.delete('/register/:username', asyncHandler(async (req, res, next) => {
  const username = normalizeNameTag(
    typeof req.params.username === 'string' ? req.params.username.trim() : '',
  ).toLowerCase();

  if (!username) {
    const error = new Error('Missing username parameter');
    error.statusCode = 400;
    return next(error);
  }

  try {
    const existing = await prisma.user.findFirst({
      where: { username, deletedAt: null },
    });

    if (!existing) {
      const notFoundError = new Error('Username not found or already deleted');
      notFoundError.statusCode = 404;
      return next(notFoundError);
    }

    await withTransaction(async (tx) => {
      await tx.user.update({
        where: { username },
        data: { deletedAt: new Date() },
      });

      // Invalidate any stale federation cache entries
      invalidateFederationCache(username, existing.address);
    });

    await recordActivity(prisma, {
      username,
      action: ACTIVITY_ACTIONS.USER_UNREGISTERED,
      metadata: { address: existing.address },
      req,
    });

    return res.status(200).json({ ok: true, username, deleted: true });
  } catch (error) {
    logger.error('Failed to unregister account:', error);
    const dbError = new Error('Failed to unregister account', { cause: error });
    dbError.statusCode = 500;
    return next(dbError);
  }
}));

// #599 — A user's own activity trail. Ownership is proven the same way the
// webhook endpoints prove it: a signature over `activity:<username>` made with
// the account key, passed in the X-Stellar-Signature header (or the body, as
// the webhook routes accept it).
router.get(
  '/users/:username/activity',
  validateSchema({ query: activityQuerySchema }),
  asyncHandler(async (req, res, next) => {
    const username = normalizeNameTag(
      typeof req.params.username === 'string' ? req.params.username.trim() : '',
    ).toLowerCase();

    if (!username) {
      return next(new ApiError('INVALID_INPUT', 'Missing username parameter.'));
    }

    let owner;
    try {
      owner = await authenticateUsernameOwner({
        username,
        signature: req.get('X-Stellar-Signature') || req.body?.signature,
        signerAddress: req.get('X-Stellar-Signer') || req.body?.signerAddress,
        operation: 'activity',
      });
    } catch (error) {
      return next(error);
    }

    const { range, error: dateError } = parseDateRange(req.query);
    if (dateError) {
      return next(new ApiError('INVALID_INPUT', dateError));
    }

    const { page, limit } = req.query;
    const { rows, total } = await listActivity(prisma, {
      username: owner.username,
      page,
      limit,
      range,
    });

    return res
      .status(200)
      .json(paginatedResponse(rows.map(serializeActivity), total, { page, limit }));
  }),
);

/**
 * @openapi
 * /lookup:
 *   get:
 *     tags:
 *       - v1
 *     description: GET /lookup
 *     responses:
 *       200:
 *         description: Success
 */
router.get('/lookup', etagCache, validateSchema({ query: lookupQuerySchema }), asyncHandler(async (req, res, next) => {
  const { address = '', search = '' } = req.query;

  if (address) {
    try {
      const result = await lookupCached(address, async () => {
        // #613 — an address can have several usernames; return the primary.
        const row = await prisma.user.findFirst({
          where: { address, deletedAt: null },
          select: { username: true },
          orderBy: PRIMARY_USERNAME_ORDER,
        });
        return row ? { username: row.username, address } : null;
      });

      if (!result) {
        const notFoundError = new Error('Username not found for this address');
        notFoundError.statusCode = 404;
        return next(notFoundError);
      }

      return res.json(result);
    } catch (error) {
      const dbError = new Error('Database lookup failed', { cause: error });
      dbError.statusCode = 500;
      return next(dbError);
    }
  }

  const { limit: cursorLimit, cursor, invalid: invalidCursor } = parseCursorQuery(req.query);
  const { page, limit, skip } = parsePagination(req.query);
  if (invalidCursor) {
    return next(new ApiError('INVALID_INPUT', 'Invalid cursor parameter'));
  }
  const where = buildUserSearchWhere(search);

  try {
    const result = await lookupUser(req.query.address, req.query.search, req.query);
    return res.json(result);
  } catch (error) {
    return next(error);
  }
}));


/**
 * @openapi
 * /users:
 *   get:
 *     tags:
 *       - v1
 *     description: GET /users
 *     responses:
 *       200:
 *         description: Success
 */
/**
 * @openapi
 * /users:
 *   get:
 *     tags:
 *       - v1
 *     description: GET /users
 *     responses:
 *       200:
 *         description: Success
 */
router.get('/users', etagCache, validateSchema({ query: usersQuerySchema }), asyncHandler(async (req, res, next) => {
  const { limit: cursorLimit, cursor, invalid: invalidCursor } = parseCursorQuery(req.query);
  const { page, limit, skip } = parsePagination(req.query);
  if (invalidCursor) {
    return next(new ApiError('INVALID_INPUT', 'Invalid cursor parameter'));
  }
  const search = req.query.search ?? null;
  const where = search ? buildUserSearchWhere(search) : { deletedAt: null };

  try {
    const result = await listUsers(req.query);
    return res.json(result);
  } catch (error) {
    return next(error);
  }
}));

module.exports = router;
