const mongoose=require("mongoose");
require("dotenv").config();

exports.connect=()=>{
    mongoose.connect(process.env.MONGODB_URL,{
        UseNewUrlParser:true,
        useUnifiedTopology:true
    })
    .then(()=>{
        console.log("DB connected Successfully")
    })
    .catch((err)=>{
        console.log("DB Connection Issue");
        console.log(err);
        process.exit(1);
    });
}