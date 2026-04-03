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

  const { data: authUser, error: createAuthError } = await client.auth.admin.createUser({
    email: normalizedEmail,
    password,
    email_confirm: true,
    user_metadata: {
      name,
      role: 'analyst'
    }
  });

  if (createAuthError || !authUser?.user) {
    return res.status(500).json({ message: createAuthError?.message || 'Failed to create Supabase user' });
  }

  const { error: profileError } = await client.from('users').upsert({
    id: authUser.user.id,
    name,
    email: normalizedEmail,
    role: 'analyst'
  });

  if (profileError) {
    return res.status(500).json({ message: profileError.message });
  }

  const { data: sessionData, error: signInError } = await authClient.auth.signInWithPassword({
    email: normalizedEmail,
    password
  });

  if (signInError || !sessionData?.session) {
    return res.status(201).json({
      token: null,
      user: {
        id: authUser.user.id,
        name,
        email: normalizedEmail,
        role: 'analyst'
      }
    });
  }

  return res.status(201).json({
    token: sessionData.session.access_token,
    user: {
      id: authUser.user.id,
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
  const { data: sessionData, error: signInError } = await authClient.auth.signInWithPassword({
    email: normalizedEmail,
    password
  });

  if (signInError || !sessionData?.session || !sessionData?.user) {
    return res.status(401).json({ message: 'Invalid credentials' });
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

exports.me = (req, res) => {
  return res.json({ user: req.user });
};
