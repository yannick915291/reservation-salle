const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

// Configuration
const PORT = 3000;
const DATA_DIR = path.join(__dirname, '../data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const RESERVATIONS_FILE = path.join(DATA_DIR, 'reservations.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

// In-memory state
let users = {};
let reservations = [];
let sessions = new Map(); // token -> {username, expires}

// Load data from files
function loadData() {
    try {
        if (fs.existsSync(USERS_FILE)) {
            users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        } else {
            // First run: create default admin (will prompt on frontend)
            users = {};
        }
        
        if (fs.existsSync(RESERVATIONS_FILE)) {
            reservations = JSON.parse(fs.readFileSync(RESERVATIONS_FILE, 'utf8'));
        } else {
            reservations = [];
        }
    } catch (e) {
        console.error('Error loading data:', e);
        users = {};
        reservations = [];
    }
}

function saveUsers() {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function saveReservations() {
    fs.writeFileSync(RESERVATIONS_FILE, JSON.stringify(reservations, null, 2));
}

// Hash password (SHA-256)
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

// Generate secure token
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Auth middleware
function authenticate(req) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
    
    const token = authHeader.split(' ')[1];
    const session = sessions.get(token);
    
    if (!session || Date.now() > session.expires) {
        sessions.delete(token);
        return null;
    }
    
    return session.username;
}

// Get user by username
function getUser(username) {
    return users[username] || null;
}

// API Response helper
function sendJSON(res, status, data) {
    res.writeHead(status, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    res.end(JSON.stringify(data));
}

function sendError(res, status, message) {
    sendJSON(res, status, { error: message });
}

// Parse body
function parseBody(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                resolve(JSON.parse(body));
            } catch {
                resolve({});
            }
        });
    });
}

// Main server
const server = http.createServer(async (req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;
    const method = req.method;

    // CORS preflight
    if (method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        });
        return res.end();
    }

    // Serve frontend static files
    if (pathname === '/' || pathname === '/index.html') {
        const frontendPath = path.join(__dirname, '../frontend/index.html');
        if (fs.existsSync(frontendPath)) {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            return res.end(fs.readFileSync(frontendPath));
        }
    }

    // API routes
    if (pathname.startsWith('/api/')) {
        let username = null;
        
        // Routes that require auth
        const protectedRoutes = ['/api/me', '/api/reservations', '/api/users'];
        if (protectedRoutes.some(r => pathname.startsWith(r))) {
            username = authenticate(req);
            if (!username) {
                return sendError(res, 401, 'Non authentifié');
            }
        }

        const user = username ? getUser(username) : null;
        const isAdmin = user && user.role === 'admin';

        // === LOGIN ===
        if (pathname === '/api/login' && method === 'POST') {
            const body = await parseBody(req);
            const { username: loginUser, password } = body;
            
            if (!loginUser || !password) {
                return sendError(res, 400, 'Identifiant et mot de passe requis');
            }
            
            const targetUser = users[loginUser.toLowerCase()];
            if (!targetUser) {
                return sendError(res, 401, 'Identifiants incorrects');
            }
            
            const hashed = hashPassword(password);
            if (targetUser.password !== hashed) {
                return sendError(res, 401, 'Identifiants incorrects');
            }
            
            // Create session
            const token = generateToken();
            const expires = Date.now() + (24 * 60 * 60 * 1000); // 24h
            sessions.set(token, { username: loginUser.toLowerCase(), expires });
            
            return sendJSON(res, 200, {
                token,
                user: {
                    username: loginUser.toLowerCase(),
                    name: targetUser.name,
                    role: targetUser.role
                }
            });
        }

        // === GET CURRENT USER ===
        if (pathname === '/api/me' && method === 'GET') {
            return sendJSON(res, 200, {
                username,
                name: user.name,
                role: user.role
            });
        }

        // === RESERVATIONS ===
        if (pathname === '/api/reservations') {
            if (method === 'GET') {
                // Return all reservations (filtered for non-admin if needed, but for simplicity return all)
                return sendJSON(res, 200, reservations);
            }
            
            if (method === 'POST') {
                const body = await parseBody(req);
                const { date, slot, motif } = body;
                
                if (!date || !slot) {
                    return sendError(res, 400, 'Date et créneau requis');
                }
                
                // Check if slot already taken
                const existing = reservations.find(r => 
                    r.date === date && r.slot === slot && r.status === 'approved'
                );
                if (existing) {
                    return sendError(res, 400, 'Ce créneau est déjà réservé');
                }
                
                const newRes = {
                    id: Date.now(),
                    date,
                    slot,
                    user: username,
                    status: 'pending',
                    motif: motif || 'Aucun motif précisé',
                    createdAt: new Date().toISOString()
                };
                
                reservations.push(newRes);
                saveReservations();
                
                return sendJSON(res, 201, newRes);
            }
        }

        // === SINGLE RESERVATION ACTIONS ===
        const resMatch = pathname.match(/^\/api\/reservations\/(\d+)\/(approve|reject|cancel)$/);
        if (resMatch) {
            const resId = parseInt(resMatch[1]);
            const action = resMatch[2];
            const resIndex = reservations.findIndex(r => r.id === resId);
            
            if (resIndex === -1) {
                return sendError(res, 404, 'Réservation introuvable');
            }
            
            const res = reservations[resIndex];
            
            if (action === 'approve' || action === 'reject') {
                if (!isAdmin) return sendError(res, 403, 'Accès réservé à l\'administrateur');
                
                if (action === 'approve') {
                    // Check if already approved
                    const already = reservations.find(r => 
                        r.date === res.date && r.slot === res.slot && r.status === 'approved' && r.id !== resId
                    );
                    if (already) {
                        return sendError(res, 400, 'Ce créneau est déjà validé');
                    }
                    
                    reservations[resIndex].status = 'approved';
                    
                    // Reject other pending for same slot
                    reservations.forEach((r, i) => {
                        if (r.date === res.date && r.slot === res.slot && r.status === 'pending' && r.id !== resId) {
                            reservations[i].status = 'rejected';
                        }
                    });
                } else {
                    reservations[resIndex].status = 'rejected';
                }
                
                saveReservations();
                return sendJSON(res, 200, reservations[resIndex]);
            }
            
            if (action === 'cancel') {
                if (res.user !== username || res.status !== 'pending') {
                    return sendError(res, 403, 'Vous ne pouvez annuler que vos demandes en attente');
                }
                reservations[resIndex].status = 'rejected';
                saveReservations();
                return sendJSON(res, 200, { message: 'Demande annulée' });
            }
        }

        // === USERS MANAGEMENT (Admin only) ===
        if (pathname === '/api/users') {
            if (!isAdmin) return sendError(res, 403, 'Accès réservé à l\'administrateur');
            
            if (method === 'GET') {
                // Return users without passwords
                const safeUsers = Object.keys(users).map(u => ({
                    username: u,
                    name: users[u].name,
                    role: users[u].role,
                    color: users[u].color
                }));
                return sendJSON(res, 200, safeUsers);
            }
            
            if (method === 'POST') {
                const body = await parseBody(req);
                const { username: newUser, name, role, password } = body;
                
                if (!newUser || !name || !password) {
                    return sendError(res, 400, 'Champs manquants');
                }
                
                if (users[newUser.toLowerCase()]) {
                    return sendError(res, 400, 'Cet identifiant existe déjà');
                }
                
                users[newUser.toLowerCase()] = {
                    role: role || 'user',
                    name,
                    password: hashPassword(password),
                    color: '#6366f1'
                };
                
                saveUsers();
                return sendJSON(res, 201, { message: 'Utilisateur créé' });
            }
        }

        // PUT /api/users/:username
        const userMatch = pathname.match(/^\/api\/users\/([^/]+)$/);
        if (userMatch && method === 'PUT') {
            if (!isAdmin) return sendError(res, 403, 'Accès réservé à l\'administrateur');
            
            const targetUsername = userMatch[1].toLowerCase();
            if (!users[targetUsername]) {
                return sendError(res, 404, 'Utilisateur introuvable');
            }
            
            const body = await parseBody(req);
            const { name, role, password } = body;
            
            if (name) users[targetUsername].name = name;
            if (role) users[targetUsername].role = role;
            if (password) users[targetUsername].password = hashPassword(password);
            
            saveUsers();
            return sendJSON(res, 200, { message: 'Utilisateur mis à jour' });
        }

        // DELETE /api/users/:username
        if (userMatch && method === 'DELETE') {
            if (!isAdmin) return sendError(res, 403, 'Accès réservé à l\'administrateur');
            
            const targetUsername = userMatch[1].toLowerCase();
            if (targetUsername === username) {
                return sendError(res, 400, 'Vous ne pouvez pas vous supprimer vous-même');
            }
            
            if (!users[targetUsername]) {
                return sendError(res, 404, 'Utilisateur introuvable');
            }
            
            delete users[targetUsername];
            saveUsers();
            return sendJSON(res, 200, { message: 'Utilisateur supprimé' });
        }

        // Default 404 for API
        return sendError(res, 404, 'Endpoint non trouvé');
    }

    // Fallback
    sendError(res, 404, 'Page non trouvée');
});

// Start server
loadData();
server.listen(PORT, () => {
    console.log(`🚀 Serveur de production démarré sur http://localhost:${PORT}`);
    console.log(`📁 Données stockées dans: ${DATA_DIR}`);
    console.log(`🔐 Mots de passe hashés avec SHA-256`);
    if (Object.keys(users).length === 0) {
        console.log(`⚠️  Aucun utilisateur. Allez sur http://localhost:${PORT} pour créer l'administrateur.`);
    }
});