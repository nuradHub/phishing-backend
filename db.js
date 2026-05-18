import mongoose from "mongoose";

const connectDB = async ()=> {
  try{
    await mongoose.connect(process.env.MONGODB_URL)
    console.log('✅✅ Connected to mongodb')
  }catch(err){
    console.log(err.message)
    process.exit(1)
  }
}

export default connectDB