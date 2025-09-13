// models/InterestRate.js
import mongoose from "mongoose";

const interestRateSchema = new mongoose.Schema({
  metalType: { 
    type: String, 
    required: true, 
    enum: ["gold", "silver"] // only gold or silver
  },
  minAmount: { 
    type: Number, 
    required: true 
  },
  maxAmount: { 
    type: Number, 
    required: true 
  },
  interest: { 
    type: Number, 
    required: true 
  },
  date: { 
    type: Date, 
    default: Date.now // automatically sets the current date
  },
});

const InterestRate = mongoose.model("InterestRate", interestRateSchema);

export default InterestRate;
