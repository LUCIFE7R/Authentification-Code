const bcrypt=require("bcrypt");
const user=require("../models/User");
const jwt=require("jsonwebtoken");
require("dotenv").config();

//signup

exports.signup= async (req,res)=>{
    try{
        const {name,email,password,role}=req.body;
        const existingUser=await User.findOne({email});
        if (existingUser){
            return res.status(400).json({
                success:false,
                message:"User already Exists",
            });
        }

        //secure Password

        let hashedPassword;
        try{
            hashedPassword=await bcrypt.hash(password,10);
        }catch(err){
            return res.status(500).json({
                success:false,
                message:"Error in hashing Password",
            });
        }

        //entry
        const User= await User.create({
            name,email,password:hashedPassword,role
        })
        return res.status(200).json({
            success:true,
            message:"User Created Successfully",
        });
    }catch(error){
        console.error(error);
        return res.status(500).json({
            success:false,
            message:"User cannot be registered, please try again later"
        });
    }
}

//login

exports.login =async(req,res)=>{
    try{
        //fetching
        const{email,password}=req.body;
        //validation
        if(!email || !password){
            return res.status(400).json({
                success:false,
                message:"Please fill all the details carefully",
            });
        }
        //registered
        let user=await user.findOne({email});
        //if not
        if(!user){
            return res.status(401).json({
                success:false,
                message:"User is not Registered",
            });
        }
        const payload={
            email:user.email,
            id:user._id,
            role:user.role,
        };
        //verify password & generate a JWT token
        if(await bcrypt.compare(password,user.password)){
            let token=jwt.sign(payload,
                process.env.JWT_SECRET,{
                    expiresIn:"2h",
                });
               
                user=user.toObject();
                user.token=token;
                user.password=undefined;

                const options={
                    expires:new Date(Date.now()+3*24*60*60*1000),
                    httpOnly:true,
                }
                res.cookie("Saket",token,options).status(200).json({
                    success:true,
                    token,
                    user,
                    message:"User Logged in Successfully",
                });
        }
        else{
            return res.status(403).json({
                success:false,
                message:"Password Incorrect",
            });
        }
    }catch(error){
        console.log(error);
        return res.status(500).json({
            success:false,
            message:"Login Failure",
        });
    }
}