const {Schema,model}=require("mongoose")

const userSchema=new Schema({
name:{type:String,required:true},
email:{type:String,required:true,unique:true},
password:{type:String,required:true},
failedLoginAttempts: {
  type: Number,
  default: 0
},
blockedUntil: {
  type: Date,
  default: null
}

},{timestamps:true})

const userModel=model("user",userSchema)
module.exports=userModel
