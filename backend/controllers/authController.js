const {
  createSupabaseAuthClient,
  createSupabaseServiceClient
} = require('../config/supabase');

const authSupabase = createSupabaseAuthClient();
const serviceSupabase = createSupabaseServiceClient();

function getSupabaseOrFail(res) {
  if (!serviceSupabase) {
    res.status(500).json({ message: 'Supabase is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.' });
    return null;
  }

  return serviceSupabase;
}

function isInvalidApiKeyError(error) {
  const message = String(error?.message || '');
  return /invalid api key|apikey|api key/i.test(message);
}

async function signInWithPasswordWithFallback(authClient, serviceClient, email, password) {
  let { data, error } = await authClient.auth.signInWithPassword({
    email,
    password
  });

  if (isInvalidApiKeyError(error) && authClient !== serviceClient) {
    const fallbackResult = await serviceClient.auth.signInWithPassword({
      email,
      password
    });
    data = fallbackResult.data;
    error = fallbackResult.error;
  }

  return { data, error };
}

async function findAuthUserByEmail(client, email) {
  let page = 1;
  const perPage = 200;

  while (true) {
    const { data, error } = await client.auth.admin.listUsers({ page, perPage });
    if (error) {
      throw error;
    }

    const users = data?.users || [];
    const matched = users.find((user) => String(user.email || '').toLowerCase() === email);
    if (matched) {
      return matched;
    }

    if (users.length < perPage) {
      return null;
    }

    page += 1;
  }
}

exports.register = async (req, res) => {
  const { name, email, password } = req.body;
  const client = getSupabaseOrFail(res);

  if (!client) {
    return;
  }

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Name, email, and password are required' });
  }

  const authClient = authSupabase || client;
  const normalizedEmail = email.toLowerCase();

  const { data: existingUser, error: lookupError } = await client
    .from('users')
    .select('id')
    .eq('email', normalizedEmail)
    .maybeSingle();

  if (lookupError) {
    return res.status(500).json({ message: lookupError.message });
  }

  if (existingUser) {
    return res.status(409).json({ message: 'Email already registered' });
  }

  let existingAuthUser = null;
  try {
    existingAuthUser = await findAuthUserByEmail(client, normalizedEmail);
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }

  if (existingAuthUser) {
    // Reconcile cases where auth.users has an account but public.users is missing.
    const { error: profileUpsertError } = await client.from('users').upsert({
      id: existingAuthUser.id,
      name,
      email: normalizedEmail,
      role: 'analyst'
    });

    if (profileUpsertError) {
      return res.status(500).json({ message: profileUpsertError.message });
    }

    const { data: existingSession, error: existingSignInError } = await signInWithPasswordWithFallback(
      authClient,
      client,
      normalizedEmail,
      password
    );

    if (!existingSignInError && existingSession?.session) {
      return res.status(200).json({
        token: existingSession.session.access_token,
        user: {
          id: existingAuthUser.id,
          name,
          email: normalizedEmail,
          role: 'analyst'
        },
        message: 'Account already existed. Signed in successfully.'
      });
    }

    return res.status(409).json({ message: 'Email already registered. Please login or reset your password.' });
  }

  let authUser;
  try {
    const { data, error: createAuthError } = await client.auth.admin.createUser({
      email: normalizedEmail,
      password,
      email_confirm: true,
      user_metadata: {
        name,
        role: 'analyst'
      }
    });

    if (createAuthError || !data?.user) {
      return res.status(500).json({ message: createAuthError?.message || 'Failed to create Supabase user' });
    }

    authUser = data.user;
  } catch (error) {
    const message = String(error?.message || '');
    if (/already registered|already exists|duplicate/i.test(message)) {
      return res.status(409).json({ message: 'Email already registered' });
    }

    return res.status(500).json({ message: message || 'Failed to create Supabase user' });
  }

  const { error: profileError } = await client.from('users').upsert({
    id: authUser.id,
    name,
    email: normalizedEmail,
    role: 'analyst'
  });

  if (profileError) {
    return res.status(500).json({ message: profileError.message });
  }

  const { data: sessionData, error: signInError } = await signInWithPasswordWithFallback(
    authClient,
    client,
    normalizedEmail,
    password
  );

  if (signInError || !sessionData?.session) {
    return res.status(201).json({
      token: null,
      user: {
        id: authUser.id,
        name,
        email: normalizedEmail,
        role: 'analyst'
      }
    });
  }

  return res.status(201).json({
    token: sessionData.session.access_token,
    user: {
      id: authUser.id,
      name,
      email: normalizedEmail,
      role: 'analyst'
    }
  });
};

exports.login = async (req, res) => {
  const { email, password } = req.body;
  const client = getSupabaseOrFail(res);

  if (!client) {
    return;
  }

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  const authClient = authSupabase || client;
  const normalizedEmail = email.toLowerCase();

  const { data: authUsers, error: authLookupError } = await client.auth.admin.listUsers();
  if (authLookupError) {
    return res.status(500).json({ message: authLookupError.message });
  }

  const authUser = authUsers?.users?.find((user) => String(user.email || '').toLowerCase() === normalizedEmail);
  if (!authUser) {
    return res.status(404).json({ message: 'Email not registered' });
  }

  const { data: sessionData, error: signInError } = await signInWithPasswordWithFallback(
    authClient,
    client,
    normalizedEmail,
    password
  );

  if (isInvalidApiKeyError(signInError)) {
    return res.status(500).json({ message: 'Supabase auth key is invalid. Check SUPABASE_ANON_KEY.' });
  }

  if (signInError || !sessionData?.session || !sessionData?.user) {
    return res.status(401).json({ message: 'Invalid password' });
  }

  const { data: profile, error: profileError } = await client
    .from('users')
    .select('id, name, email, role')
    .eq('id', sessionData.user.id)
    .maybeSingle();

  if (profileError) {
    return res.status(500).json({ message: profileError.message });
  }

  return res.json({
    token: sessionData.session.access_token,
    user: {
      id: sessionData.user.id,
      name: profile?.name || sessionData.user.user_metadata?.name || sessionData.user.email,
      email: profile?.email || sessionData.user.email,
      role: profile?.role || sessionData.user.user_metadata?.role || 'analyst'
    }
  });
};

exports.forgotPassword = async (req, res) => {
  const { email } = req.body;
  const client = getSupabaseOrFail(res);

  if (!client) {
    return;
  }

  if (!email || !String(email).trim()) {
    return res.status(400).json({ message: 'Email is required' });
  }

  const authClient = authSupabase || client;
  const normalizedEmail = String(email).toLowerCase().trim();
  const configuredClientUrl = String(process.env.CLIENT_URL || '').trim();
  const resetOptions = configuredClientUrl
    ? { redirectTo: `${configuredClientUrl.replace(/\/+$/, '')}/login.html?reset=1` }
    : undefined;

  let { error } = await authClient.auth.resetPasswordForEmail(normalizedEmail, resetOptions);

  if (isInvalidApiKeyError(error) && authClient !== client) {
    const fallbackResult = await client.auth.resetPasswordForEmail(normalizedEmail, resetOptions);
    error = fallbackResult.error;
  }

  if (error) {
    if (isInvalidApiKeyError(error)) {
      return res.status(500).json({ message: 'Supabase auth key is invalid. Check SUPABASE_ANON_KEY.' });
    }

    const message = String(error.message || 'Unable to send password reset email');
    if (/redirect url|redirect_to|not allowed/i.test(message)) {
      return res.status(400).json({ message: 'Password reset redirect URL is not allowed. Add CLIENT_URL/login.html to Supabase Auth Redirect URLs.' });
    }

    if (/rate limit|too many/i.test(message)) {
      return res.status(429).json({ message: 'Too many reset attempts. Please wait and try again.' });
    }

    return res.status(500).json({ message });
  }

  return res.json({
    message: 'If the email exists, a password reset link has been sent.'
  });
};

exports.me = (req, res) => {
  return res.json({ user: req.user });
};
