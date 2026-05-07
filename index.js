require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cron = require('node-cron');
const db = require('./db'); // Now imports the Postgres pool we just made

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ==========================================
// AUTH MIDDLEWARE (Guard)
// ==========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access denied. No token provided." });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid token." });
        req.user = user; 
        next();
    });
};

const getUserId = (req) => req.user.user_id || req.user.id;

// ==========================================
// 1. USER & AUTH MODULE
// ==========================================
app.post('/api/users', async (req, res) => {
    try {
        const { username, email, password, bio } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const result = await db.query(
            `INSERT INTO Users (username, email, password_hash, bio, status) 
             VALUES ($1, $2, $3, $4, 'active') RETURNING user_id`,
            [username, email, hashedPassword, bio || '']
        );
        
        const user = { user_id: result.rows[0].user_id, username, email };
        const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user });
    } catch (err) { 
        // 🚨 THIS IS THE NEW LINE: It forces the terminal to print the exact database error
        console.error("🔥 REGISTRATION DB ERROR:", err); 
        res.status(500).json({ error: "Registration failed." }); 
    }
});
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const result = await db.query("SELECT * FROM Users WHERE email = $1 AND status = 'active'", [email]);

        const user = result.rows[0];
        if (!user || !(await bcrypt.compare(password, user.password_hash))) 
            return res.status(401).json({ error: "Invalid credentials." });

        const payload = { user_id: user.user_id, username: user.username, email: user.email };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { ...payload, bio: user.bio, profile_picture: user.profile_picture } });
    } catch (err) { res.status(500).json({ error: "Login failed." }); }
});

app.put('/api/users/profile', authenticateToken, async (req, res) => {
    try {
        const { username, bio, profile_picture, password } = req.body;
        let query = "UPDATE Users SET username = $1, bio = $2, profile_picture = $3";
        let params = [username, bio, profile_picture, getUserId(req)];

        if (password) {
            const hashed = await bcrypt.hash(password, 10);
            query += ", password_hash = $5";
            params.push(hashed);
        }
        query += " WHERE user_id = $4";
        await db.query(query, params);
        res.json({ message: "Profile updated successfully." });
    } catch (err) { res.status(500).json({ error: "Profile update failed." }); }
});

// ==========================================
// 2. SOCIAL MODULE (Friends, Search, Chat)
// ==========================================
app.get('/api/users/search', authenticateToken, async (req, res) => {
    try {
        const { q } = req.query;
        const userId = getUserId(req);
        const result = await db.query(`
            SELECT user_id, username, profile_picture, bio FROM Users 
            WHERE (username ILIKE $1 OR email ILIKE $1) AND user_id <> $2
            AND user_id NOT IN (
                SELECT receiver_id FROM FriendRequests WHERE sender_id = $2 AND status IN ('accepted', 'pending')
                UNION
                SELECT sender_id FROM FriendRequests WHERE receiver_id = $2 AND status IN ('accepted', 'pending')
            )
        `, [`%${q}%`, userId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Search failed." }); }
});

app.get('/api/friends', authenticateToken, async (req, res) => {
    try {
        const result = await db.query(`
            SELECT u.user_id, u.username, u.profile_picture FROM Users u
            WHERE u.user_id IN (
                SELECT receiver_id FROM FriendRequests WHERE sender_id = $1 AND status = 'accepted'
                UNION
                SELECT sender_id FROM FriendRequests WHERE receiver_id = $1 AND status = 'accepted'
            )
        `, [getUserId(req)]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Failed to fetch circle." }); }
});

app.get('/api/friends/requests', authenticateToken, async (req, res) => {
    try {
        const result = await db.query(`
            SELECT fr.request_id, u.username, u.profile_picture, u.bio, fr.sender_id
            FROM FriendRequests fr JOIN Users u ON fr.sender_id = u.user_id
            WHERE fr.receiver_id = $1 AND fr.status = 'pending'
        `, [getUserId(req)]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Failed to fetch requests." }); }
});

app.get('/api/friends/requests/count', authenticateToken, async (req, res) => {
    try {
        const result = await db.query("SELECT COUNT(*) AS count FROM FriendRequests WHERE receiver_id = $1 AND status = 'pending'", [getUserId(req)]);
        res.json({ count: parseInt(result.rows[0].count) });
    } catch (err) { res.status(500).json({ error: "Failed to fetch count." }); }
});

app.post('/api/friends/request', authenticateToken, async (req, res) => {
    try {
        await db.query("INSERT INTO FriendRequests (sender_id, receiver_id) VALUES ($1, $2)", [getUserId(req), req.body.receiver_id]);
        res.json({ message: "Request transmitted." });
    } catch (err) { res.status(500).json({ error: "Request failed." }); }
});

app.put('/api/friends/requests/:id', authenticateToken, async (req, res) => {
    try {
        await db.query("UPDATE FriendRequests SET status = $1 WHERE request_id = $2", [req.body.status, req.params.id]);
        res.json({ message: `Request ${req.body.status}.` });
    } catch (err) { res.status(500).json({ error: "Response failed." }); }
});

app.delete('/api/friends/:friendId', authenticateToken, async (req, res) => {
    try {
        const uid = getUserId(req);
        const fid = req.params.friendId;
        
        // SPLIT INTO SEPARATE QUERIES
        await db.query(`DELETE FROM Pull_Requests WHERE source_repo_id IN (SELECT repo_id FROM Repositories WHERE owner_id = $1 AND forked_from_repo_id IN (SELECT repo_id FROM Repositories WHERE owner_id = $2)) OR source_repo_id IN (SELECT repo_id FROM Repositories WHERE owner_id = $2 AND forked_from_repo_id IN (SELECT repo_id FROM Repositories WHERE owner_id = $1))`, [uid, fid]);
        
        await db.query(`DELETE FROM FriendRequests WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)`, [uid, fid]);
        
        await db.query(`DELETE FROM Contributors WHERE (repo_id IN (SELECT repo_id FROM Repositories WHERE owner_id = $1) AND user_id = $2) OR (repo_id IN (SELECT repo_id FROM Repositories WHERE owner_id = $2) AND user_id = $1)`, [uid, fid]);
        
        await db.query(`DELETE FROM Repositories WHERE (owner_id = $1 AND forked_from_repo_id IN (SELECT repo_id FROM Repositories WHERE owner_id = $2)) OR (owner_id = $2 AND forked_from_repo_id IN (SELECT repo_id FROM Repositories WHERE owner_id = $1))`, [uid, fid]);
        
        res.json({ message: "Friend removed. Access revoked and forks deleted." });
    } catch (err) { res.status(500).json({ error: "Friend removal failed." }); }
});

app.get('/api/messages/:friendId', authenticateToken, async (req, res) => {
    try {
        const result = await db.query(
            `SELECT * FROM Messages WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1) ORDER BY sent_at ASC`, 
            [getUserId(req), req.params.friendId]
        );
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Failed to fetch messages." }); }
});

app.post('/api/messages', authenticateToken, async (req, res) => {
    try {
        await db.query(`INSERT INTO Messages (sender_id, receiver_id, content) VALUES ($1, $2, $3)`, [getUserId(req), req.body.receiver_id, req.body.content]);
        res.json({ message: "Message sent." });
    } catch (err) { res.status(500).json({ error: "Transmission failed." }); }
});

// ==========================================
// 3. REPOSITORY CORE MODULE
// ==========================================
app.get('/api/users/contributions', authenticateToken, async (req, res) => {
    try {
        const result = await db.query(`
            SELECT TO_CHAR(created_at, 'YYYY-MM-DD') as date, COUNT(*) as count 
            FROM Commits WHERE user_id = $1 AND created_at >= CURRENT_DATE - INTERVAL '365 days'
            GROUP BY TO_CHAR(created_at, 'YYYY-MM-DD')
        `, [getUserId(req)]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Failed to fetch contributions." }); }
});

app.put('/api/repos/:id/visibility', authenticateToken, async (req, res) => {
    try {
        await db.query("UPDATE Repositories SET visibility = $1 WHERE repo_id = $2", [req.body.visibility, req.params.id]);
        res.json({ message: "Visibility updated." });
    } catch (err) { res.status(500).json({ error: "Visibility update failed." }); }
});

app.post('/api/repos', authenticateToken, async (req, res) => {
    try {
        await db.query('INSERT INTO Repositories (name, visibility, owner_id) VALUES ($1, $2, $3)', [req.body.name, req.body.visibility.toLowerCase(), getUserId(req)]);
        res.json({ message: "Repository initialized." });
    } catch (err) { res.status(500).json({ error: "Repo creation failed." }); }
});

app.get('/api/repos', authenticateToken, async (req, res) => {
    try {
        const result = await db.query(`
            SELECT r.*, u.username as owner_name FROM Repositories r JOIN Users u ON r.owner_id = u.user_id 
            WHERE r.owner_id = $1 OR r.repo_id IN (SELECT repo_id FROM Contributors WHERE user_id = $1) ORDER BY created_at DESC
        `, [getUserId(req)]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Sync failed." }); }
});

app.get('/api/repos/global', authenticateToken, async (req, res) => {
    try {
        const result = await db.query(`
            SELECT r.*, u.username as owner_name FROM Repositories r JOIN Users u ON r.owner_id = u.user_id 
            WHERE r.visibility = 'public' AND r.name ILIKE $1
        `, [`%${req.query.q}%`]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Search failed." }); }
});

app.get('/api/repos/:id', authenticateToken, async (req, res) => {
    try {
        const repo = await db.query(`SELECT r.*, u.username as owner_name, u.profile_picture as owner_pfp FROM Repositories r JOIN Users u ON r.owner_id = u.user_id WHERE r.repo_id = $1`, [req.params.id]);
        if (repo.rows.length === 0) return res.status(404).json({ error: "Not found." });

        const items = await db.query('SELECT * FROM vw_folder_contents WHERE repo_id = $1', [req.params.id]);
        const prs = await db.query("SELECT * FROM vw_active_prs WHERE target_repo_id = $1 AND status = 'open'", [req.params.id]);
        const contributors = await db.query('SELECT u.user_id, u.username, u.profile_picture FROM Contributors c JOIN Users u ON c.user_id = u.user_id WHERE c.repo_id = $1', [req.params.id]);
        
        let canUpstream = false;
        if (repo.rows[0].forked_from_repo_id) {
            const parentOwner = await db.query("SELECT owner_id FROM Repositories WHERE repo_id = $1", [repo.rows[0].forked_from_repo_id]);
            if (parentOwner.rows.length > 0) {
                const friendCheck = await db.query(
                    "SELECT 1 FROM FriendRequests WHERE status = 'accepted' AND ((sender_id=$1 AND receiver_id=$2) OR (sender_id=$2 AND receiver_id=$1))",
                    [getUserId(req), parentOwner.rows[0].owner_id]
                );
                canUpstream = friendCheck.rows.length > 0;
            }
        }
        res.json({ repo: repo.rows[0], items: items.rows, pullRequests: prs.rows, contributors: contributors.rows, canUpstream });
    } catch (err) { res.status(500).json({ error: "Retrieval failed." }); }
});

app.delete('/api/repos/:id', authenticateToken, async (req, res) => {
    try {
        const repo = await db.query('SELECT owner_id FROM Repositories WHERE repo_id = $1', [req.params.id]);
        if (!repo.rows[0] || repo.rows[0].owner_id !== getUserId(req)) return res.status(403).json({ error: "Unauthorized." });

        await db.query('DELETE FROM Pull_Requests WHERE target_repo_id = $1', [req.params.id]);
        await db.query('DELETE FROM Repositories WHERE repo_id = $1', [req.params.id]);
        res.json({ message: "Purged successfully." });
    } catch (err) { res.status(500).json({ error: "Purge failed." }); }
});

app.post('/api/repos/:id/fork', authenticateToken, async (req, res) => {
    try {
        const original = await db.query("SELECT name, description FROM Repositories WHERE repo_id = $1", [req.params.id]);
        const { name, description } = original.rows[0];

        const newRepo = await db.query(
            `INSERT INTO Repositories (name, description, owner_id, forked_from_repo_id) VALUES ($1, $2, $3, $4) RETURNING repo_id`,
            [`${name}-fork`, description, getUserId(req), req.params.id]
        );
        const newRepoId = newRepo.rows[0].repo_id;

        // SPLIT INTO SEPARATE QUERIES
        await db.query(`
            INSERT INTO Folders (repo_id, name, parent_folder_id, is_deleted)
            SELECT $1, name, NULL, FALSE FROM Folders WHERE repo_id = $2 AND is_deleted = FALSE
        `, [newRepoId, req.params.id]);

        await db.query(`
            INSERT INTO Files (repo_id, folder_id, name, file_type, content, is_deleted)
            SELECT $1, NULL, name, file_type, content, FALSE FROM Files WHERE repo_id = $2 AND folder_id IS NULL AND is_deleted = FALSE
        `, [newRepoId, req.params.id]);

        await db.query(`
            INSERT INTO Files (repo_id, folder_id, name, file_type, content, is_deleted)
            SELECT $1, nf.folder_id, f.name, f.file_type, f.content, FALSE
            FROM Files f
            JOIN Folders of ON f.folder_id = of.folder_id
            JOIN Folders nf ON of.name = nf.name
            WHERE f.repo_id = $2 AND nf.repo_id = $1 AND f.is_deleted = FALSE
        `, [newRepoId, req.params.id]);

        res.json({ message: "Fork successful", newRepoId });
    } catch (err) { 
        console.error(err);
        res.status(500).json({ error: "Fork failed." }); 
    }
});
// ==========================================
// 4. VERSION CONTROL (Commits, PRs, Merge)
// ==========================================
app.post('/api/repos/:id/commit', authenticateToken, async (req, res) => {
    try {
        const { name, content, type, parent_id } = req.body;
        const userId = getUserId(req);

        const dupCheck = await db.query(`
            SELECT 1 FROM vw_folder_contents WHERE repo_id = $1 AND name = $2 AND COALESCE(parent, -1) = COALESCE($3, -1)
            UNION SELECT 1 FROM Pull_Requests WHERE target_repo_id = $1 AND title = $2 AND status = 'open'
        `, [req.params.id, name, parent_id || null]);
        
        if (dupCheck.rows.length > 0) return res.status(400).json({ error: "Name already exists here." });

        const repo = await db.query('SELECT owner_id FROM Repositories WHERE repo_id = $1', [req.params.id]);
        const isOwner = repo.rows[0].owner_id === userId;

        if (!isOwner) {
            const contribCheck = await db.query("SELECT 1 FROM Contributors WHERE repo_id = $1 AND user_id = $2", [req.params.id, userId]);
            if (contribCheck.rows.length === 0) return res.status(403).json({ error: "Access Denied." });
        }

        if (isOwner) {
            if (type === 'folder') {
                await db.query(`INSERT INTO Folders (repo_id, parent_folder_id, name, is_deleted) VALUES ($1, $2, $3, FALSE)`, [req.params.id, parent_id || null, name]); 
            } else {
                await db.query(`INSERT INTO Files (repo_id, folder_id, name, content, file_type, is_deleted) VALUES ($1, $2, $3, $4, 'file', FALSE)`, [req.params.id, parent_id || null, name, content || '']);
            }
            await db.query(`INSERT INTO Commits (repo_id, user_id, message) VALUES ($1, $2, 'Direct Commit')`, [req.params.id, userId]);
            res.json({ message: "Commit successful." });
        } else {
            await db.query(`INSERT INTO Pull_Requests (source_repo_id, target_repo_id, created_by, title, description, status, folder_id) VALUES ($1, $1, $2, $3, $4, 'open', $5)`, [req.params.id, userId, name, content, parent_id || null]);
            res.json({ message: "Proposal submitted for audit." });
        }
    } catch (err) { res.status(500).json({ error: "Commit failed." }); }
});

app.post('/api/repos/:id/upstream-pr', authenticateToken, async (req, res) => {
    try {
        const repoCheck = await db.query("SELECT forked_from_repo_id FROM Repositories WHERE repo_id = $1", [req.params.id]);
        const parentRepoId = repoCheck.rows[0]?.forked_from_repo_id;
        
        if (!parentRepoId) return res.status(400).json({ error: "Not a fork." });

        await db.query(
            `INSERT INTO Pull_Requests (source_repo_id, target_repo_id, created_by, title, description, status) VALUES ($1, $2, $3, $4, $5, 'open')`,
            [req.params.id, parentRepoId, getUserId(req), req.body.title, req.body.description]
        );
        res.json({ message: "Proposal transmitted to mainstream." });
    } catch (err) { res.status(500).json({ error: "Upstream sync failed." }); }
});

app.post('/api/repos/:id/reject/:pr_id', authenticateToken, async (req, res) => {
    try {
        await db.query("UPDATE Pull_Requests SET status = 'rejected' WHERE pr_id = $1", [req.params.pr_id]);
        res.json({ message: "Proposal rejected." });
    } catch (err) { res.status(500).json({ error: "Reject failed." }); }
});

app.post('/api/repos/:id/merge/:pr_Id', authenticateToken, async (req, res) => {
    try {
        const prQuery = await db.query("SELECT * FROM Pull_Requests WHERE pr_id = $1", [req.params.pr_Id]);
        const pr = prQuery.rows[0];
        if (!pr) return res.status(404).json({ error: "PR not found." });

        if (pr.source_repo_id === pr.target_repo_id) {
            await db.query(`INSERT INTO Files (repo_id, folder_id, name, content, file_type, is_deleted) VALUES ($1, $2, $3, $4, 'file', FALSE)`, [req.params.id, pr.folder_id || null, pr.title, pr.description]);
        } else {
            // SPLIT INTO SEPARATE QUERIES
            await db.query(`
                INSERT INTO Files (repo_id, folder_id, name, content, file_type, is_deleted)
                SELECT $1, folder_id, name, content, file_type, FALSE FROM Files WHERE repo_id = $2 AND is_deleted = FALSE AND name NOT IN (SELECT name FROM Files WHERE repo_id = $1 AND is_deleted = FALSE)
            `, [pr.target_repo_id, pr.source_repo_id]);
            
            await db.query(`
                UPDATE Files t SET content = s.content FROM Files s WHERE t.name = s.name AND t.repo_id = $1 AND s.repo_id = $2 AND s.is_deleted = FALSE
            `, [pr.target_repo_id, pr.source_repo_id]);
        }

        await db.query("UPDATE Pull_Requests SET status = 'merged' WHERE pr_id = $1", [req.params.pr_Id]);
        await db.query(`INSERT INTO Commits (repo_id, user_id, message) VALUES ($1, $2, 'Merged PR')`, [req.params.id, pr.created_by]);
        res.json({ message: "Merge sequence complete." });
    } catch (err) { res.status(500).json({ error: "Merge failed." }); }
});

app.post('/api/repos/:id/contributors', authenticateToken, async (req, res) => {
    try {
        await db.query("INSERT INTO Contributors (repo_id, user_id, role) VALUES ($1, $2, 'contributor')", [req.params.id, req.body.friend_id]);
        res.json({ message: "Contributor added." });
    } catch (err) { res.status(500).json({ error: "Addition failed." }); }
});

app.delete('/api/repos/:id/contributors/:user_id', authenticateToken, async (req, res) => {
    try {
        await db.query("DELETE FROM Contributors WHERE repo_id = $1 AND user_id = $2", [req.params.id, req.params.user_id]);
        res.json({ message: "Access revoked." });
    } catch (err) { res.status(500).json({ error: "Revocation failed." }); }
});

app.get('/api/repos/:id/leaderboard', authenticateToken, async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM vw_contributor_leaderboard WHERE repo_id = $1 ORDER BY commits DESC", [req.params.id]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Leaderboard failure." }); }
});

// ==========================================
// 5. RECYCLE BIN MODULE (Soft Delete)
// ==========================================
app.delete('/api/repos/:id/:type/:item_id', authenticateToken, async (req, res) => {
    try {
        const table = req.params.type === 'folders' ? 'Folders' : 'Files';
        const idCol = req.params.type === 'folders' ? 'folder_id' : 'file_id';

        await db.query(`UPDATE ${table} SET is_deleted = TRUE WHERE ${idCol} = $1`, [req.params.item_id]);
        await db.query("INSERT INTO Trash (repo_id, item_id, item_type, deleted_by) VALUES ($1, $2, $3, $4)", [req.params.id, req.params.item_id, req.params.type === 'folders' ? 'folder' : 'file', getUserId(req)]);
        res.json({ message: "Moved to Recycle Bin." });
    } catch (err) { res.status(500).json({ error: "Soft delete failed." }); }
});

app.get('/api/repos/:id/trash', authenticateToken, async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM vw_recycle_bin WHERE repo_id = $1', [req.params.id]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Trash access failed." }); }
});

app.post('/api/repos/:id/restore/:trash_id', authenticateToken, async (req, res) => {
    try {
        const itemResult = await db.query('SELECT * FROM Trash WHERE trash_id = $1', [req.params.trash_id]);
        const item = itemResult.rows[0];
        if (!item) return res.status(404).json({ error: "Node not found." });

        const table = item.item_type === 'folder' ? 'Folders' : 'Files';
        const idCol = item.item_type === 'folder' ? 'folder_id' : 'file_id';

        await db.query(`UPDATE ${table} SET is_deleted = FALSE WHERE ${idCol} = $1`, [item.item_id]);
        await db.query('DELETE FROM Trash WHERE trash_id = $1', [req.params.trash_id]);
        res.json({ message: "Node restored." });
    } catch (err) { res.status(500).json({ error: "Restoration failed." }); }
});

app.get('/api/files/:id', authenticateToken, async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM Files WHERE file_id = $1', [req.params.id]);
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: "File load failure." }); }
});

// ==========================================
// 6. CRON JOBS (Maintenance)
// ==========================================
cron.schedule('0 0 * * *', async () => {
    try {
        await db.query(`
            DELETE FROM Files WHERE file_id IN (SELECT item_id FROM Trash WHERE item_type = 'file' AND deleted_at < NOW() - INTERVAL '10 days');
            DELETE FROM Folders WHERE folder_id IN (SELECT item_id FROM Trash WHERE item_type = 'folder' AND deleted_at < NOW() - INTERVAL '10 days');
            DELETE FROM Trash WHERE deleted_at < NOW() - INTERVAL '10 days';
        `);
    } catch (err) { console.error('Maintenance failure:', err); }
});

app.listen(port, () => console.log(`🚀 Mainframe fully operational on port ${port}`));