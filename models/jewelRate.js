// models/JewelRate.js
import mongoose from "mongoose";

const jewelRateSchema = new mongoose.Schema({
  metalType: { 
    type: String, 
    required: true, 
    enum: ["gold", "silver"], // only allow these two metals
  },
  rate: { 
    type: Number, 
    required: true 
  },
  date: { 
    type: Date, 
    default: Date.now // automatically sets current date if not provided
  },
});

const JewelRate = mongoose.model("JewelRate", jewelRateSchema);

export default JewelRate;
