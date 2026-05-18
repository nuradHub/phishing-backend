import jwt from 'jsonwebtoken'

const UserProtected = async (req, res, next)=> {
  let token
  if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')){

    try{
      token = req.headers.authorization.split(' ')[1]
      const decoded = jwt.verify(token, process.env.JWT_SECRET)

      req.userId = decoded.userId
      req.role = decoded.role

      next()

    }catch(err){
      console.log(err.message)
      res.status(401).json({message: 'Unathorized'})
    }
  }

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized: Invalid or expired token' })
  }

}
export default UserProtected