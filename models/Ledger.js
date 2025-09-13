// ./models/Ledger.js
import mongoose from 'mongoose';

const ledgerSchema = new mongoose.Schema({
  queryDate: { type: Date, required: true }, // The date for which this ledger entry was generated
  voucherId: { type: mongoose.Schema.Types.ObjectId, ref: 'Voucher', required: true }, // Reference to Voucher
  customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer', required: true }, // Reference to Customer
  billNo: { type: String, required: true },
  customerCode: { type: String }, // Customer ID/code
  customerName: { type: String, required: true },
  customerPhone: { type: String },
  customerPhoto: { type: String }, // URL or path to photo
  jewelType: { type: String, enum: ['gold', 'silver', 'diamond'], default: 'gold' },
  grossWeight: { type: Number, default: 0 },
  netWeight: { type: Number, default: 0 },
  jewelryItems: [{ type: mongoose.Schema.Types.Mixed }], // Allow any type for jewelry items
  finalLoanAmount: { type: Number, default: 0 },
  interestRate: { type: Number, default: 0 },
  interestAmount: { type: Number, default: 0 },
  totalAmount: { type: Number, default: 0 }, // overallLoanAmount
  repaidAmount: { type: Number, default: 0 },
  balanceAmount: { type: Number, default: 0 },
  disbursementDate: { type: Date, required: true },
  dueDate: { type: Date, required: true },
  lastPaymentDate: { type: Date },
  status: { 
    type: String, 
    enum: ['active', 'partial', 'overdue', 'closed', 'Active', 'Partial', 'Overdue', 'Closed'], // Accept both cases
    default: 'active' 
  },
  daysOverdue: { type: Number, default: 0 },
  loanDuration: { type: Number, default: 0 }, // In days
  paymentProgress: { type: Number, default: 0 }, // Percentage
  monthsPaid: { type: Number, default: 0 },
  closedDate: { type: Date },
  category: { 
    type: String, 
    enum: ['all', 'active', 'overdue', 'closed'], 
    required: true 
  }, // To categorize as in the controller (allLoans, activeLoans, etc.)
}, {
  timestamps: true
});

// Indexes for better querying in Compass
ledgerSchema.index({ queryDate: 1 });
ledgerSchema.index({ customerId: 1 });
ledgerSchema.index({ voucherId: 1 });
ledgerSchema.index({ status: 1 });
ledgerSchema.index({ category: 1 });

export default mongoose.model('Ledger', ledgerSchema);