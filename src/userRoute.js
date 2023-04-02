const express=require("express")
const UserModel=require("./userModel")
const app=express.Router()
const jwt=require("jsonwebtoken")
const argon2=require("argon2")


app.post("/signup",async(req,res)=>{
const {name,email,password}=req.body
//console.log(username,email,password);
const hash=await argon2.hash(password)
try{
    const user=new UserModel({name,email,password:hash})
    await user.save()
    return res.status(201).send("user created")

}
catch(e){
    console.log(e.message)
    return res.send(e.message)
}
});


app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    
    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    const isMatch =await argon2.verify(user.password,password);
    if (!isMatch) {
      user.failedLoginAttempts++;
      await user.save();
      
      if (user.failedLoginAttempts >= 5) {
        const blockTime = Date.now() + 24 * 60 * 60 * 1000;
        user.blockedUntil = blockTime;
        await user.save();
        return res.status(401).send({ message: `User is blocked for 24 hours till ${new Date(blockTime).toLocaleString()}` });
      }else{
        return res.status(401).send({ message: 'Invalid email or password' });
      }
      
     
    }
    if (user.blockedUntil && user.blockedUntil > Date.now()) {
        return res.status(401).send({ message: `User is blocked until ${new Date(user.blockedUntil).toLocaleString()}` });
      }

    user.failedLoginAttempts = 0;
    await user.save();
    
    const token=jwt.sign({id:user._id,name:user.name,email:user.email},"SECRET",{expiresIn:"24 hours"})
    const refreshToken=jwt.sign({id:user._id,name:user.name,email:user.email},"REFRESH",{expiresIn:"7 days"})
    return res.status(201).send({message:"login sucess",token,refreshToken,user})  });
  



//Get
app.get("/:id",async(req,res)=>{


        try{
            const user=await UserModel.findById(req.params.id)
            const {password,failedLoginAttempts,blockedUntil,...others}=user._doc
            return res.send(others)
        }
        catch(e){
            res.status(500).send(e.message)
        }

 

   
});




module.exports=app;
