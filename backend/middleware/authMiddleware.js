const { createSupabaseServiceClient } = require('../config/supabase');

const supabase = createSupabaseServiceClient();

async function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : req.headers['x-auth-token'];

  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  if (!supabase) {
    return res.status(500).json({ message: 'Supabase is not configured' });
  }

  const { data: userData, error: authError } = await supabase.auth.getUser(token);

  if (authError || !userData?.user) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }

  const { data: profile, error: profileError } = await supabase
    .from('users')
    .select('id, name, email, role')
    .eq('id', userData.user.id)
    .maybeSingle();

  if (profileError) {
    return res.status(500).json({ message: profileError.message });
  }

  req.user = profile || {
    id: userData.user.id,
    name: userData.user.user_metadata?.name || userData.user.email,
    email: userData.user.email,
    role: userData.user.user_metadata?.role || 'analyst'
  };

  return next();
}

module.exports = authMiddleware;
