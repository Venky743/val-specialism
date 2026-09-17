import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import path from 'path';
import { fileURLToPath } from 'url';
import { MongoClient } from 'mongodb';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const PORT = Number(process.env.PORT || 8080);

const JWT_SECRET =
  process.env.JWT_SECRET || 'CHANGE_ME_IN_ENV';

const COOKIE_SECURE =
  String(process.env.COOKIE_SECURE || 'false').toLowerCase() === 'true';

const ADMIN_EMAIL =
  String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();

const PRICE =
  Number(process.env.VALIDATION_PRICE_USD || '149.00');

const INDIA_SMALL_PRICE =
  Number(process.env.INDIA_SMALL_PRICE_INR || '1499');

const INDIA_ENTERPRISE_PRICE =
  Number(process.env.INDIA_ENTERPRISE_PRICE_INR || '3999');

const RAZORPAY_KEY_ID =
  process.env.RAZORPAY_KEY_ID || '';

const RAZORPAY_KEY_SECRET =
  process.env.RAZORPAY_KEY_SECRET || '';

const RAZORPAY_WEBHOOK_SECRET =
  process.env.RAZORPAY_WEBHOOK_SECRET || '';

const PAYPAL_MODE =
  process.env.PAYPAL_MODE === 'live' ? 'live' : 'sandbox';

const PAYPAL_BASE =
  PAYPAL_MODE === 'live'
    ? 'https://api-m.paypal.com'
    : 'https://api-m.sandbox.paypal.com';

const SUPPORT_EMAIL =
  String(
    process.env.SUPPORT_EMAIL || 'venkypd252@gmail.com'
  ).trim();

const SMTP_HOST =
  String(process.env.SMTP_HOST || '').trim();

const SMTP_PORT =
  Number(process.env.SMTP_PORT || '587');

const SMTP_USER =
  String(process.env.SMTP_USER || '').trim();

const SMTP_PASS =
  String(process.env.SMTP_PASS || '').trim();

const SMTP_SECURE =
  String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true';

const mailer =
  SMTP_HOST && SMTP_USER && SMTP_PASS
    ? nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: SMTP_SECURE,
        auth: {
          user: SMTP_USER,
          pass: SMTP_PASS
        }
      })
    : null;


/* =========================================================
   MONGODB DATABASE
   ========================================================= */

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  throw new Error('MONGODB_URI is not configured.');
}

const MONGODB_DB = 'val_specialism';
const MONGODB_COLLECTION = 'app_state';

const mongoClient = new MongoClient(MONGODB_URI, {
  family: 4,
  tls: true
});

let mongoCollection;

let dbState = {
  users: [],
  validations: [],
  payments: [],
  webhook_events: [],
  feedback: []
};

async function loadDb() {
  await mongoClient.connect();

  const database = mongoClient.db(MONGODB_DB);

  mongoCollection =
    database.collection(MONGODB_COLLECTION);

  const saved =
    await mongoCollection.findOne({ _id: 'main' });

  if (saved) {
    for (const key of [
      'users',
      'validations',
      'payments',
      'webhook_events',
      'feedback'
    ]) {
      if (Array.isArray(saved[key])) {
        dbState[key] = saved[key];
      }
    }
  } else {
    await mongoCollection.insertOne({
      _id: 'main',
      ...dbState
    });
  }

  for (const u of dbState.users) {
    u.login_count = Number(u.login_count || 0);

    if (
      !Object.prototype.hasOwnProperty.call(
        u,
        'last_login_at'
      )
    ) {
      u.last_login_at = null;
    }
  }

  for (const v of dbState.validations) {
    if (
      !Object.prototype.hasOwnProperty.call(
        v,
        'downloaded_at'
      )
    ) {
      v.downloaded_at = null;
    }
  }

  console.log('MongoDB connected (val_specialism)');
}

let saveQueue = Promise.resolve();

function saveDb() {
  saveQueue = saveQueue
    .then(async () => {
      if (!mongoCollection) {
        throw new Error('MongoDB is not connected.');
      }

      await mongoCollection.replaceOne(
        { _id: 'main' },
        {
          _id: 'main',
          ...dbState
        },
        {
          upsert: true
        }
      );
    })
    .catch(err => {
      console.error('MongoDB save error:', err);
    });

  return saveQueue;
}

function findOne(table, predicate) {
  return dbState[table].find(predicate) || null;
}

function insert(table, row) {
  dbState[table].push(row);
  saveDb();
  return row;
}

function updateOne(table, predicate, mutator) {
  const row = findOne(table, predicate);

  if (row) {
    mutator(row);
    saveDb();
  }

  return row;
}

function allSorted(
  table,
  sortFn,
  limit = 500
) {
  return [...dbState[table]]
    .sort(sortFn)
    .slice(0, limit);
}


/* =========================================================
   HELPERS
   ========================================================= */

function now() {
  return new Date().toISOString();
}

function jsonError(res, code, message) {
  return res
    .status(code)
    .json({
      ok: false,
      error: message
    });
}

function signToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      name: user.name,
      country: user.country
    },
    JWT_SECRET,
    {
      expiresIn: '7d'
    }
  );
}

function auth(req, res, next) {
  try {
    const token = req.cookies.val_session;

    if (!token) {
      return jsonError(
        res,
        401,
        'Not authenticated.'
      );
    }

    const payload = jwt.verify(
      token,
      JWT_SECRET
    );

    const foundUser = findOne(
      'users',
      u => u.id === payload.sub
    );

    const user = foundUser
      ? {
          id: foundUser.id,
          name: foundUser.name,
          email: foundUser.email,
          country: foundUser.country
        }
      : null;

    if (!user) {
      return jsonError(
        res,
        401,
        'Account not found.'
      );
    }

    req.user = user;
    next();

  } catch {
    return jsonError(
      res,
      401,
      'Session expired. Please login again.'
    );
  }
}


/* =========================================================
   PAYPAL
   ========================================================= */

async function paypalToken() {
  if (
    !process.env.PAYPAL_CLIENT_ID ||
    !process.env.PAYPAL_CLIENT_SECRET
  ) {
    throw new Error(
      'PayPal credentials are not configured.'
    );
  }

  const basic = Buffer
    .from(
      `${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`
    )
    .toString('base64');

  const r = await fetch(
    `${PAYPAL_BASE}/v1/oauth2/token`,
    {
      method: 'POST',
      headers: {
        Authorization: `Basic ${basic}`,
        'Content-Type':
          'application/x-www-form-urlencoded'
      },
      body:
        'grant_type=client_credentials'
    }
  );

  const data = await r.json();

  if (!r.ok) {
    throw new Error(
      data.error_description ||
      'Could not authenticate with PayPal.'
    );
  }

  return data.access_token;
}

async function paypalRequest(
  url,
  options = {}
) {
  const token = await paypalToken();

  const r = await fetch(
    `${PAYPAL_BASE}${url}`,
    {
      ...options,
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization:
          `Bearer ${token}`,
        ...(options.headers || {})
      }
    }
  );

  const text = await r.text();

  let data = {};

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }

  if (!r.ok) {
    throw new Error(
      data.message ||
      data.name ||
      `PayPal request failed (${r.status}).`
    );
  }

  return data;
}


/* =========================================================
   MIDDLEWARE
   ========================================================= */

app.use(
  express.json({
    limit: '1mb',
    verify: (req, res, buf) => {
      req.rawBody = buf;
    }
  })
);

app.use(cookieParser());


/* =========================================================
   CONFIG
   ========================================================= */

app.get(
  '/api/config',
  (req, res) =>
    res.json({
      ok: true,
      paypalClientId:
        process.env.PAYPAL_CLIENT_ID || '',
      paypalMode: PAYPAL_MODE,
      razorpayKeyId:
        RAZORPAY_KEY_ID,
      indiaPrices: {
        small: INDIA_SMALL_PRICE,
        enterprise:
          INDIA_ENTERPRISE_PRICE
      },
      internationalPrice: PRICE,
      internationalCurrency: 'USD'
    })
);


/* =========================================================
   AUTH - REGISTER
   ========================================================= */

app.post(
  '/api/auth/register',
  async (req, res) => {
    try {
      const name =
        String(req.body.name || '').trim();

      const email =
        String(req.body.email || '')
          .trim()
          .toLowerCase();

      const password =
        String(req.body.password || '');

      const country =
        String(req.body.country || '')
          .trim()
          .toUpperCase();

      if (
        !name ||
        !email ||
        !password ||
        !country
      ) {
        return jsonError(
          res,
          400,
          'Complete all fields.'
        );
      }

      if (!['IN', 'INTL'].includes(country)) {
        return jsonError(
          res,
          400,
          'Select a valid country option.'
        );
      }

      if (!/^\S+@\S+\.\S+$/.test(email)) {
        return jsonError(
          res,
          400,
          'Enter a valid email address.'
        );
      }

      if (password.length < 6) {
        return jsonError(
          res,
          400,
          'Password must be at least 6 characters.'
        );
      }

      if (
        findOne(
          'users',
          u => u.email === email
        )
      ) {
        return jsonError(
          res,
          409,
          'An account already exists. Please login.'
        );
      }

      const user = {
        id: crypto.randomUUID(),
        name,
        email,
        country,
        password_hash:
          await bcrypt.hash(password, 12),
        created_at: now(),
        login_count: 0,
        last_login_at: null
      };

      insert('users', user);

      res
        .status(201)
        .json({
          ok: true,
          message:
            'Account created successfully. Please login to continue.'
        });

    } catch (e) {
      console.error(e);

      jsonError(
        res,
        500,
        'Could not create account.'
      );
    }
  }
);


/* =========================================================
   AUTH - LOGIN
   ========================================================= */

app.post(
  '/api/auth/login',
  async (req, res) => {
    try {
      const email =
        String(req.body.email || '')
          .trim()
          .toLowerCase();

      const password =
        String(req.body.password || '');

      const user = findOne(
        'users',
        u => u.email === email
      );

      if (!user) {
        return jsonError(
          res,
          401,
          'No account found. Please create an account first.'
        );
      }

      if (
        !(await bcrypt.compare(
          password,
          user.password_hash
        ))
      ) {
        return jsonError(
          res,
          401,
          'Invalid email or password.'
        );
      }

      user.login_count =
        Number(user.login_count || 0) + 1;

      user.last_login_at = now();

      await saveDb();

      const token =
        signToken(user);

      res.cookie(
        'val_session',
        token,
        {
          httpOnly: true,
          sameSite: 'lax',
          secure: COOKIE_SECURE,
          maxAge:
            7 * 24 * 60 * 60 * 1000,
          path: '/'
        }
      );

      res.json({
        ok: true,
        user: {
          name: user.name,
          email: user.email,
          country: user.country
        }
      });

    } catch (e) {
      console.error(e);

      jsonError(
        res,
        500,
        'Login failed.'
      );
    }
  }
);


/* =========================================================
   AUTH - LOGOUT / ME
   ========================================================= */

app.post(
  '/api/auth/logout',
  (req, res) => {
    res.clearCookie(
      'val_session',
      {
        httpOnly: true,
        sameSite: 'lax',
        secure: COOKIE_SECURE,
        path: '/'
      }
    );

    res.json({
      ok: true
    });
  }
);

app.get(
  '/api/auth/me',
  auth,
  (req, res) =>
    res.json({
      ok: true,
      user: req.user
    })
);


/* =========================================================
   VALIDATION SESSIONS
   ========================================================= */

app.post(
  '/api/validation-sessions',
  auth,
  async (req, res) => {
    const id =
      `VAL-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

    insert(
      'validations',
      {
        id,
        user_id: req.user.id,
        status: 'PREVIEW',
        created_at: now(),
        paid_at: null,
        downloaded_at: null
      }
    );

    res
      .status(201)
      .json({
        ok: true,
        validationId: id
      });
  }
);


/* =========================================================
   PLANS
   ========================================================= */

function getPlanForUser(
  user,
  plan
) {
  if (user.country === 'IN') {
    if (plan === 'india_small') {
      return {
        plan,
        amount: INDIA_SMALL_PRICE,
        currency: 'INR',
        provider: 'razorpay',
        label:
          'Small & Medium Business'
      };
    }

    if (
      plan === 'india_enterprise'
    ) {
      return {
        plan,
        amount:
          INDIA_ENTERPRISE_PRICE,
        currency: 'INR',
        provider: 'razorpay',
        label:
          'Large / Enterprise'
      };
    }

    return null;
  }

  if (plan === 'international') {
    return {
      plan,
      amount: PRICE,
      currency: 'USD',
      provider: 'paypal',
      label:
        'Business Validation'
    };
  }

  return null;
}


/* =========================================================
   PAYPAL ORDER
   ========================================================= */

app.post(
  '/api/paypal/orders',
  auth,
  async (req, res) => {
    try {
      if (req.user.country !== 'INTL') {
        return jsonError(
          res,
          403,
          'PayPal is available here for international accounts only.'
        );
      }

      const plan =
        getPlanForUser(
          req.user,
          'international'
        );

      const validationId =
        String(
          req.body.validationId || ''
        );

      const v = findOne(
        'validations',
        x =>
          x.id === validationId &&
          x.user_id === req.user.id
      );

      if (!v) {
        return jsonError(
          res,
          404,
          'Validation session not found. Run validation first.'
        );
      }

      const existing =
        findOne(
          'payments',
          x =>
            x.validation_id ===
            validationId
        );

      if (
        existing?.status === 'PAID'
      ) {
        return res.json({
          ok: true,
          paid: true,
          provider:
            existing.provider,
          orderId:
            existing.paypal_order_id,
          status: 'PAID'
        });
      }

      const order =
        await paypalRequest(
          '/v2/checkout/orders',
          {
            method: 'POST',
            headers: {
              'PayPal-Request-Id':
                crypto.randomUUID()
            },
            body:
              JSON.stringify({
                intent: 'CAPTURE',
                purchase_units: [
                  {
                    reference_id:
                      validationId,
                    custom_id:
                      validationId,
                    description:
                      'Val Specialism — Business Validation',
                    amount: {
                      currency_code:
                        'USD',
                      value:
                        plan.amount.toFixed(2)
                    }
                  }
                ]
              })
          }
        );

      if (existing) {
        updateOne(
          'payments',
          x =>
            x.validation_id ===
            validationId,
          x => {
            x.provider =
              'paypal';

            x.paypal_order_id =
              order.id;

            x.amount =
              plan.amount.toFixed(2);

            x.currency = 'USD';
            x.plan = plan.plan;
            x.status = 'PENDING';
          }
        );
      } else {
        insert(
          'payments',
          {
            id:
              crypto.randomUUID(),
            validation_id:
              validationId,
            user_id:
              req.user.id,
            provider:
              'paypal',
            plan:
              plan.plan,
            paypal_order_id:
              order.id,
            amount:
              plan.amount.toFixed(2),
            currency:
              'USD',
            status:
              'PENDING',
            created_at:
              now(),
            paid_at:
              null,
            paypal_capture_id:
              null
          }
        );
      }

      res.json({
        ok: true,
        orderId:
          order.id,
        status:
          'PENDING',
        amount:
          plan.amount.toFixed(2),
        currency:
          'USD',
        provider:
          'paypal'
      });

    } catch (e) {
      console.error(e);

      jsonError(
        res,
        500,
        e.message ||
          'Could not create PayPal order.'
      );
    }
  }
);


/* =========================================================
   PAYPAL CAPTURE
   ========================================================= */

app.post(
  '/api/paypal/orders/:orderId/capture',
  auth,
  async (req, res) => {
    try {
      if (req.user.country !== 'INTL') {
        return jsonError(
          res,
          403,
          'PayPal is available here for international accounts only.'
        );
      }

      const p = findOne(
        'payments',
        x =>
          x.paypal_order_id ===
            req.params.orderId &&
          x.user_id ===
            req.user.id
      );

      if (!p) {
        return jsonError(
          res,
          404,
          'Payment order not found.'
        );
      }

      const result =
        await paypalRequest(
          `/v2/checkout/orders/${encodeURIComponent(req.params.orderId)}/capture`,
          {
            method: 'POST',
            headers: {
              'PayPal-Request-Id':
                crypto.randomUUID()
            }
          }
        );

      const capture =
        result.purchase_units?.[0]
          ?.payments?.captures?.[0];

      if (
        result.status ===
          'COMPLETED' ||
        capture?.status ===
          'COMPLETED'
      ) {
        markPaid(
          p.validation_id,
          result.id,
          capture?.id
        );
      }

      const updated =
        findOne(
          'payments',
          x =>
            x.validation_id ===
            p.validation_id
        );

      res.json({
        ok: true,
        status:
          updated.status,
        paymentId:
          result.id,
        captureId:
          capture?.id || null,
        paidAt:
          updated.paid_at
      });

    } catch (e) {
      console.error(e);

      jsonError(
        res,
        500,
        e.message ||
          'Payment capture failed.'
      );
    }
  }
);


/* =========================================================
   RAZORPAY
   ========================================================= */

async function razorpayRequest(
  endpoint,
  method = 'GET',
  body = null
) {
  if (
    !RAZORPAY_KEY_ID ||
    !RAZORPAY_KEY_SECRET
  ) {
    throw new Error(
      'Razorpay credentials are not configured.'
    );
  }

  const auth =
    Buffer.from(
      `${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`
    ).toString('base64');

  const opts = {
    method,
    headers: {
      Authorization:
        `Basic ${auth}`,
      'Content-Type':
        'application/json'
    }
  };

  if (body) {
    opts.body =
      JSON.stringify(body);
  }

  const r = await fetch(
    `https://api.razorpay.com/v1${endpoint}`,
    opts
  );

  const text =
    await r.text();

  let data = {};

  try {
    data = text
      ? JSON.parse(text)
      : {};
  } catch {
    data = {
      raw: text
    };
  }

  if (!r.ok) {
    throw new Error(
      data.error?.description ||
      data.error?.reason ||
      `Razorpay request failed (${r.status}).`
    );
  }

  return data;
}


/* =========================================================
   RAZORPAY ORDER
   ========================================================= */

app.post(
  '/api/razorpay/orders',
  auth,
  async (req, res) => {
    try {
      if (req.user.country !== 'IN') {
        return jsonError(
          res,
          403,
          'Razorpay is available here for India accounts only.'
        );
      }

      const planName =
        String(
          req.body.plan || ''
        );

      const plan =
        getPlanForUser(
          req.user,
          planName
        );

      if (!plan) {
        return jsonError(
          res,
          400,
          'Invalid India plan.'
        );
      }

      const validationId =
        String(
          req.body.validationId || ''
        );

      const v = findOne(
        'validations',
        x =>
          x.id === validationId &&
          x.user_id ===
            req.user.id
      );

      if (!v) {
        return jsonError(
          res,
          404,
          'Validation session not found. Run validation first.'
        );
      }

      const existing =
        findOne(
          'payments',
          x =>
            x.validation_id ===
            validationId
        );

      if (
        existing?.status === 'PAID'
      ) {
        return res.json({
          ok: true,
          paid: true,
          provider:
            existing.provider,
          orderId:
            existing.razorpay_order_id,
          status: 'PAID'
        });
      }

      const order =
        await razorpayRequest(
          '/orders',
          'POST',
          {
            amount:
              Math.round(
                plan.amount * 100
              ),
            currency:
              'INR',
            receipt:
              validationId,
            notes: {
              validation_id:
                validationId,
              plan:
                plan.plan,
              user_id:
                req.user.id
            }
          }
        );

      if (existing) {
        updateOne(
          'payments',
          x =>
            x.validation_id ===
            validationId,
          x => {
            x.provider =
              'razorpay';

            x.razorpay_order_id =
              order.id;

            x.amount =
              plan.amount.toFixed(2);

            x.currency =
              'INR';

            x.plan =
              plan.plan;

            x.status =
              'PENDING';
          }
        );
      } else {
        insert(
          'payments',
          {
            id:
              crypto.randomUUID(),
            validation_id:
              validationId,
            user_id:
              req.user.id,
            provider:
              'razorpay',
            plan:
              plan.plan,
            razorpay_order_id:
              order.id,
            amount:
              plan.amount.toFixed(2),
            currency:
              'INR',
            status:
              'PENDING',
            created_at:
              now(),
            paid_at:
              null,
            razorpay_payment_id:
              null,
            razorpay_signature:
              null
          }
        );
      }

      res.json({
        ok: true,
        orderId:
          order.id,
        status:
          'PENDING',
        amount:
          plan.amount,
        currency:
          'INR',
        provider:
          'razorpay',
        keyId:
          RAZORPAY_KEY_ID,
        plan:
          plan.plan,
        label:
          plan.label
      });

    } catch (e) {
      console.error(e);

      jsonError(
        res,
        500,
        e.message ||
          'Could not create Razorpay order.'
      );
    }
  }
);


/* =========================================================
   RAZORPAY VERIFY
   ========================================================= */

app.post(
  '/api/razorpay/verify',
  auth,
  async (req, res) => {
    try {
      if (req.user.country !== 'IN') {
        return jsonError(
          res,
          403,
          'Razorpay is available here for India accounts only.'
        );
      }

      const {
        validationId,
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature
      } = req.body || {};

      const p = findOne(
        'payments',
        x =>
          x.validation_id ===
            validationId &&
          x.user_id ===
            req.user.id &&
          x.razorpay_order_id ===
            razorpay_order_id
      );

      if (!p) {
        return jsonError(
          res,
          404,
          'Payment order not found.'
        );
      }

      const expected =
        crypto
          .createHmac(
            'sha256',
            RAZORPAY_KEY_SECRET
          )
          .update(
            `${razorpay_order_id}|${razorpay_payment_id}`
          )
          .digest('hex');

      const provided =
        String(
          razorpay_signature || ''
        );

      if (
        expected.length !==
        provided.length
      ) {
        return jsonError(
          res,
          400,
          'Invalid Razorpay payment signature.'
        );
      }

      if (
        !crypto.timingSafeEqual(
          Buffer.from(expected),
          Buffer.from(provided)
        )
      ) {
        return jsonError(
          res,
          400,
          'Invalid Razorpay payment signature.'
        );
      }

      updateOne(
        'payments',
        x => x.id === p.id,
        x => {
          x.razorpay_payment_id =
            razorpay_payment_id;

          x.razorpay_signature =
            razorpay_signature;
        }
      );

      markPaid(
        validationId,
        razorpay_order_id,
        razorpay_payment_id
      );

      const updated =
        findOne(
          'payments',
          x => x.id === p.id
        );

      res.json({
        ok: true,
        status:
          updated.status,
        paidAt:
          updated.paid_at
      });

    } catch (e) {
      console.error(e);

      jsonError(
        res,
        500,
        e.message ||
          'Payment verification failed.'
      );
    }
  }
);


/* =========================================================
   RAZORPAY WEBHOOK
   ========================================================= */

app.post(
  '/api/razorpay/webhook',
  (req, res) => {
    try {
      if (!RAZORPAY_WEBHOOK_SECRET) {
        return jsonError(
          res,
          503,
          'Razorpay webhook is not configured.'
        );
      }

      const signature =
        req.headers[
          'x-razorpay-signature'
        ];

      const expected =
        crypto
          .createHmac(
            'sha256',
            RAZORPAY_WEBHOOK_SECRET
          )
          .update(
            req.rawBody ||
              Buffer.from(
                JSON.stringify(
                  req.body
                )
              )
          )
          .digest('hex');

      const provided =
        String(signature || '');

      if (
        !signature ||
        expected.length !==
          provided.length ||
        !crypto.timingSafeEqual(
          Buffer.from(expected),
          Buffer.from(provided)
        )
      ) {
        return jsonError(
          res,
          400,
          'Invalid Razorpay webhook signature.'
        );
      }

      const eventId =
        req.headers[
          'x-razorpay-event-id'
        ] ||
        crypto
          .createHash('sha256')
          .update(
            JSON.stringify(
              req.body
            )
          )
          .digest('hex');

      if (
        findOne(
          'webhook_events',
          x =>
            x.id ===
            `rz_${eventId}`
        )
      ) {
        return res.sendStatus(200);
      }

      insert(
        'webhook_events',
        {
          id:
            `rz_${eventId}`,
          received_at:
            now()
        }
      );

      const event =
        req.body || {};

      const payment =
        event.payload?.payment
          ?.entity;

      if (
        event.event ===
          'payment.captured' ||
        event.event ===
          'order.paid'
      ) {
        const orderId =
          payment?.order_id ||
          event.payload?.order
            ?.entity?.id;

        const p = orderId
          ? findOne(
              'payments',
              x =>
                x.razorpay_order_id ===
                orderId
            )
          : null;

        if (p) {
          markPaid(
            p.validation_id,
            orderId,
            payment?.id || null
          );
        }

      } else if (
        event.event ===
        'payment.failed'
      ) {
        const orderId =
          payment?.order_id;

        if (orderId) {
          updateOne(
            'payments',
            x =>
              x.razorpay_order_id ===
                orderId &&
              x.status !== 'PAID',
            x => {
              x.status =
                'FAILED';
            }
          );
        }

      } else if (
        event.event ===
        'refund.processed'
      ) {
        const paymentId =
          event.payload?.refund
            ?.entity?.payment_id;

        if (paymentId) {
          updateOne(
            'payments',
            x =>
              x.razorpay_payment_id ===
              paymentId,
            x => {
              x.status =
                'REFUNDED';
            }
          );
        }
      }

      res.sendStatus(200);

    } catch (e) {
      console.error(
        'Razorpay webhook error',
        e
      );

      jsonError(
        res,
        500,
        'Webhook processing failed.'
      );
    }
  }
);


/* =========================================================
   MARK PAID
   ========================================================= */

function markPaid(
  validationId,
  orderId,
  captureId
) {
  const t = now();

  updateOne(
    'payments',
    x =>
      x.validation_id ===
      validationId,
    x => {
      x.status = 'PAID';

      if (orderId) {
        if (
          x.provider ===
          'razorpay'
        ) {
          x.razorpay_order_id =
            x.razorpay_order_id ||
            orderId;
        } else {
          x.paypal_order_id =
            x.paypal_order_id ||
            orderId;
        }
      }

      if (captureId) {
        if (
          x.provider ===
          'razorpay'
        ) {
          x.razorpay_payment_id =
            x.razorpay_payment_id ||
            captureId;
        } else {
          x.paypal_capture_id =
            x.paypal_capture_id ||
            captureId;
        }
      }

      x.paid_at =
        x.paid_at || t;
    }
  );

  updateOne(
    'validations',
    x =>
      x.id === validationId,
    x => {
      x.status = 'PAID';
      x.paid_at =
        x.paid_at || t;
    }
  );
}


/* =========================================================
   PAYMENT STATUS
   ========================================================= */

app.get(
  '/api/payments/:validationId',
  auth,
  (req, res) => {
    const p = findOne(
      'payments',
      x =>
        x.validation_id ===
          req.params.validationId &&
        x.user_id ===
          req.user.id
    );

    if (!p) {
      return res.json({
        ok: true,
        status: 'NOT_STARTED'
      });
    }

    res.json({
      ok: true,
      ...p
    });
  }
);


/* =========================================================
   PAYPAL WEBHOOK
   ========================================================= */

app.post(
  '/api/paypal/webhook',
  async (req, res) => {
    try {
      const event =
        req.body;

      if (
        !process.env.PAYPAL_WEBHOOK_ID
      ) {
        return jsonError(
          res,
          503,
          'PayPal webhook is not configured.'
        );
      }

      if (
        findOne(
          'webhook_events',
          x =>
            x.id === event.id
        )
      ) {
        return res.sendStatus(200);
      }

      const headers =
        req.headers;

      const verify =
        await paypalRequest(
          '/v1/notifications/verify-webhook-signature',
          {
            method: 'POST',
            body:
              JSON.stringify({
                auth_algo:
                  headers[
                    'paypal-auth-algo'
                  ],
                cert_url:
                  headers[
                    'paypal-cert-url'
                  ],
                transmission_id:
                  headers[
                    'paypal-transmission-id'
                  ],
                transmission_sig:
                  headers[
                    'paypal-transmission-sig'
                  ],
                transmission_time:
                  headers[
                    'paypal-transmission-time'
                  ],
                webhook_id:
                  process.env
                    .PAYPAL_WEBHOOK_ID,
                webhook_event:
                  event
              })
          }
        );

      if (
        verify.verification_status !==
        'SUCCESS'
      ) {
        return jsonError(
          res,
          400,
          'Invalid PayPal webhook signature.'
        );
      }

      insert(
        'webhook_events',
        {
          id:
            event.id,
          received_at:
            now()
        }
      );

      const resource =
        event.resource || {};

      if (
        event.event_type ===
        'PAYMENT.CAPTURE.COMPLETED'
      ) {
        const orderId =
          resource
            .supplementary_data
            ?.related_ids
            ?.order_id;

        const p = orderId
          ? findOne(
              'payments',
              x =>
                x.paypal_order_id ===
                orderId
            )
          : null;

        if (p) {
          markPaid(
            p.validation_id,
            orderId,
            resource.id
          );
        }

      } else if (
        event.event_type ===
        'CHECKOUT.ORDER.COMPLETED'
      ) {
        const orderId =
          resource.id;

        const p =
          findOne(
            'payments',
            x =>
              x.paypal_order_id ===
              orderId
          );

        if (
          p &&
          resource.status ===
            'COMPLETED'
        ) {
          markPaid(
            p.validation_id,
            orderId,
            null
          );
        }

      } else if (
        event.event_type ===
        'PAYMENT.CAPTURE.DENIED'
      ) {
        const orderId =
          resource
            .supplementary_data
            ?.related_ids
            ?.order_id;

        if (orderId) {
          updateOne(
            'payments',
            x =>
              x.paypal_order_id ===
                orderId &&
              x.status !== 'PAID',
            x => {
              x.status =
                'FAILED';
            }
          );
        }

      } else if (
        event.event_type ===
        'PAYMENT.CAPTURE.REFUNDED'
      ) {
        const orderId =
          resource
            .supplementary_data
            ?.related_ids
            ?.order_id;

        if (orderId) {
          updateOne(
            'payments',
            x =>
              x.paypal_order_id ===
              orderId,
            x => {
              x.status =
                'REFUNDED';
            }
          );
        }
      }

      res.sendStatus(200);

    } catch (e) {
      console.error(
        'Webhook error',
        e
      );

      return jsonError(
        res,
        500,
        'Webhook processing failed.'
      );
    }
  }
);


/* =========================================================
   USAGE STATS
   ========================================================= */

app.get(
  '/api/usage/stats',
  auth,
  (req, res) => {
    const loggedInPeople =
      dbState.users.filter(
        u =>
          Number(
            u.login_count || 0
          ) > 0
      ).length;

    const validationsGenerated =
      dbState.validations.length;

    const pdfDownloads =
      dbState.validations.filter(
        v => v.downloaded_at
      ).length;

    const freeReviews =
      dbState.validations.filter(
        v =>
          v.status !== 'PAID' &&
          !v.downloaded_at
      ).length;

    const isAdmin =
      Boolean(
        ADMIN_EMAIL &&
        req.user.email.toLowerCase() ===
          ADMIN_EMAIL.toLowerCase()
      );

    const stats = {
      loggedInPeople,
      validationsGenerated,
      pdfDownloads
    };

    if (isAdmin) {
      stats.freeReviews =
        freeReviews;
    }

    res.json({
      ok: true,
      stats,
      isAdmin
    });
  }
);


/* =========================================================
   PDF DOWNLOAD
   ========================================================= */

app.post(
  '/api/usage/pdf-download',
  auth,
  (req, res) => {
    const validationId =
      String(
        req.body?.validationId || ''
      );

    const v = findOne(
      'validations',
      x =>
        x.id === validationId &&
        x.user_id ===
          req.user.id
    );

    if (!v) {
      return jsonError(
        res,
        404,
        'Validation session not found.'
      );
    }

    if (v.status !== 'PAID') {
      return jsonError(
        res,
        403,
        'Payment is required before downloading the PDF.'
      );
    }

    v.downloaded_at =
      v.downloaded_at ||
      now();

    saveDb();

    res.json({
      ok: true,
      downloadedAt:
        v.downloaded_at
    });
  }
);


/* =========================================================
   FEEDBACK
   ========================================================= */

app.post(
  '/api/feedback',
  auth,
  async (req, res) => {
    const reason =
      String(
        req.body?.reason || ''
      ).trim();

    const usefulness =
      String(
        req.body?.usefulness || ''
      ).trim();

    const problem =
      String(
        req.body?.problem || ''
      ).trim();

    const details =
      String(
        req.body?.details || ''
      )
        .trim()
        .slice(0, 2000);

    if (
      !reason ||
      !usefulness ||
      !problem
    ) {
      return jsonError(
        res,
        400,
        'Please answer all three questions.'
      );
    }

    const feedback = {
      id:
        crypto.randomUUID(),
      user_id:
        req.user.id,
      email:
        req.user.email,
      reason,
      usefulness,
      problem,
      details,
      created_at:
        now()
    };

    insert(
      'feedback',
      feedback
    );

    try {
      if (
        !process.env.RESEND_API_KEY ||
        !process.env.RESEND_FROM_EMAIL
      ) {
        throw new Error(
          'Resend email is not configured.'
        );
      }

      const response =
        await fetch(
          'https://api.resend.com/emails',
          {
            method: 'POST',
            headers: {
              Authorization:
                `Bearer ${process.env.RESEND_API_KEY}`,
              'Content-Type':
                'application/json'
            },
            body:
              JSON.stringify({
                from:
                  process.env
                    .RESEND_FROM_EMAIL,
                to:
                  SUPPORT_EMAIL,
                reply_to:
                  req.user.email,
                subject:
                  `Val Specialism Feedback — ${req.user.email}`,
                text: [
                  `User: ${req.user.email}`,
                  `Reason: ${reason}`,
                  `What would make Val Specialism more useful: ${usefulness}`,
                  `Validation/data problem: ${problem}`,
                  `Additional details: ${details || '(none)'}`,
                  `Submitted: ${feedback.created_at}`
                ].join('\n\n')
              })
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data?.message ||
            'Resend email failed'
        );
      }

      res
        .status(201)
        .json({
          ok: true,
          emailSent: true
        });

    } catch (err) {
      console.error(
        'Feedback email failed:',
        err?.message || err
      );

      res
        .status(201)
        .json({
          ok: true,
          emailSent: false,
          warning:
            'Feedback was saved, but the email could not be delivered. Please email ' +
            SUPPORT_EMAIL +
            ' directly.'
        });
    }
  }
);


/* =========================================================
   ADMIN PAYMENTS
   ========================================================= */

app.get(
  '/api/admin/payments',
  auth,
  (req, res) => {
    if (
      !ADMIN_EMAIL ||
      req.user.email.toLowerCase() !==
        ADMIN_EMAIL
    ) {
      return jsonError(
        res,
        403,
        'Admin access required.'
      );
    }

    const rows =
      allSorted(
        'payments',
        (a, b) =>
          b.created_at.localeCompare(
            a.created_at
          )
      ).map(p => {
        const u =
          findOne(
            'users',
            x =>
              x.id ===
              p.user_id
          ) || {};

        return {
          ...p,
          name:
            u.name || '',
          email:
            u.email || ''
        };
      });

    res.json({
      ok: true,
      rows
    });
  }
);


/* =========================================================
   HEALTH
   ========================================================= */

app.get(
  '/api/health',
  (req, res) =>
    res.json({
      ok: true,
      paypalMode:
        PAYPAL_MODE,
      configured:
        Boolean(
          (
            process.env
              .PAYPAL_CLIENT_ID &&
            process.env
              .PAYPAL_CLIENT_SECRET
          ) ||
          (
            RAZORPAY_KEY_ID &&
            RAZORPAY_KEY_SECRET
          )
        )
    })
);


/* =========================================================
   STATIC FILES
   ========================================================= */

app.use(
  express.static(
    path.join(
      __dirname,
      'public'
    )
  )
);

app.get(
  '/admin',
  auth,
  (req, res) => {
    if (
      !ADMIN_EMAIL ||
      req.user.email.toLowerCase() !==
        ADMIN_EMAIL
    ) {
      return res
        .status(403)
        .send(
          'Admin access required.'
        );
    }

    res.sendFile(
      path.join(
        __dirname,
        'admin.html'
      )
    );
  }
);

app.get(
  /.*/,
  (req, res) =>
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'index.html'
      )
    )
);


/* =========================================================
   START SERVER ONLY AFTER MONGODB LOADS
   ========================================================= */

loadDb()
  .then(() => {
    app.listen(
      PORT,
      '0.0.0.0',
      () => {
        console.log(
          `Val Specialism running on port ${PORT} (${PAYPAL_MODE})`
        );
      }
    );
  })
  .catch(err => {
    console.error(
      'MongoDB startup error:',
      err
    );

    process.exit(1);
  });
