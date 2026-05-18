const AdminProtected = (req, res, next) => {
    try {
        if (req.role !== 'admin') {
            return res.status(403).json({ message: "Forbidden: Admin access required." });
        }
        next();
    } catch (err) {
        return res.status(401).json({ error: "Unauthorized: Invalid session token." });
    }
};
export default AdminProtected