import Voucher from '../models/Voucher.js';
import Customer from '../models/Customer.js';
import Ledger from '../models/Ledger.js';

// Controller to get ledger data and store in ledger collection
export const getLedger = async (req, res) => {
  try {
    console.log('=== LEDGER API CALLED ===');
    const { date } = req.query;
    const queryDate = date ? new Date(date) : new Date();
    queryDate.setHours(0, 0, 0, 0); // Start of day
    console.log('Query Date:', queryDate);

    // Check if ledger data already exists for this date
    const existingLedgerCount = await Ledger.countDocuments({ queryDate });
    console.log('Existing ledger entries for this date:', existingLedgerCount);
    
    // If no ledger data exists for this date, generate and store it
    if (existingLedgerCount === 0) {
      console.log(`Generating ledger data for ${queryDate.toDateString()}...`);
      
      // Check voucher count
      const voucherCount = await Voucher.countDocuments();
      console.log('Total vouchers in database:', voucherCount);
      
      if (voucherCount === 0) {
        console.log('No vouchers found. Inserting test data...');
        const customer = await Customer.findOne() || await Customer.create({
          customerId: "CUST001",
          fullName: "John Doe",
          phoneNumber: "9876543210",
          photo: "http://localhost:5000/uploads/customer1.jpg"
        });
        
        const testVoucher = await Voucher.create({
          billNo: "TEST001",
          customer: customer._id,
          jewelType: "gold",
          grossWeight: 50,
          netWeight: 48,
          loanAmount: 100000,
          finalLoanAmount: 95000,
          interestRate: 12,
          interestAmount: 1000,
          overallLoanAmount: 96000,
          disbursementDate: new Date("2025-08-10"),
          dueDate: new Date("2026-08-10"),
          paymentHistory: [{ date: new Date("2025-09-10"), amount: 1000, months: 1 }],
          status: "Active",
          monthsPaid: 1,
          totalInterestPaid: 1000
        });
        console.log('Test voucher created:', testVoucher._id);
      }

      // Fetch all vouchers and populate customer data
      let vouchers = await Voucher.find()
        .populate('customer', 'customerId fullName phoneNumber photo')
        .lean();
      
      console.log('Found vouchers:', vouchers.length);

      // Filter vouchers active on the query date
      const originalCount = vouchers.length;
      vouchers = vouchers.filter(voucher => {
        const disbursement = new Date(voucher.disbursementDate);
        const due = new Date(voucher.dueDate);
        return disbursement <= queryDate && (due >= queryDate || voucher.status === 'Closed');
      });
      console.log(`Filtered vouchers: ${originalCount} -> ${vouchers.length}`);

      // Create ledger entries for each voucher
      const ledgerEntries = [];
      
      for (const voucher of vouchers) {
        const customer = voucher.customer || {};
        
        // Normalize status to lowercase
        const normalizedStatus = (voucher.status || 'active').toLowerCase();
        
        // Determine category based on status
        let category = 'all';
        if (normalizedStatus === 'active' || normalizedStatus === 'partial') {
          category = 'active';
        } else if (normalizedStatus === 'overdue') {
          category = 'overdue';
        } else if (normalizedStatus === 'closed') {
          category = 'closed';
        }

        const ledgerEntry = {
          queryDate,
          voucherId: voucher._id,
          customerId: voucher.customer ? voucher.customer._id : null,
          billNo: voucher.billNo || 'N/A',
          customerCode: customer.customerId || 'N/A',
          customerName: customer.fullName || 'N/A',
          customerPhone: customer.phoneNumber || 'N/A',
          customerPhoto: customer.photo || null,
          jewelType: voucher.jewelType || 'gold',
          grossWeight: voucher.grossWeight || 0,
          netWeight: voucher.netWeight || 0,
          jewelryItems: Array.isArray(voucher.jewelryItems) ? voucher.jewelryItems : [],
          finalLoanAmount: voucher.finalLoanAmount || 0,
          interestRate: voucher.interestRate || 0,
          interestAmount: voucher.interestAmount || 0,
          totalAmount: voucher.overallLoanAmount || 0,
          repaidAmount: voucher.repaidAmount || 0,
          balanceAmount: voucher.balanceAmount || 0,
          disbursementDate: voucher.disbursementDate,
          dueDate: voucher.dueDate,
          lastPaymentDate: voucher.lastPaymentDate,
          status: normalizedStatus, // Use normalized lowercase status
          daysOverdue: voucher.daysOverdue || 0,
          loanDuration: voucher.loanDuration || 0,
          paymentProgress: voucher.paymentProgress || 0,
          monthsPaid: voucher.monthsPaid || 0,
          closedDate: voucher.closedDate,
          category
        };

        ledgerEntries.push(ledgerEntry);
      }

      console.log('Ledger entries to insert:', ledgerEntries.length);

      // Insert ledger entries into database
      if (ledgerEntries.length > 0) {
        try {
          const insertResult = await Ledger.insertMany(ledgerEntries);
          console.log(`SUCCESS! Inserted ${insertResult.length} ledger entries for ${queryDate.toDateString()}`);
          console.log('First inserted entry ID:', insertResult[0]._id);
        } catch (insertError) {
          console.error('Insert error details:', insertError);
          throw insertError;
        }
      } else {
        console.log('No ledger entries to insert');
      }
    } else {
      console.log('Using existing ledger data from database');
    }

    // Fetch ledger data from database
    const allLedgerEntries = await Ledger.find({ queryDate }).lean();
    console.log('Retrieved ledger entries from DB:', allLedgerEntries.length);

    // Categorize loans from ledger data
    const allLoans = allLedgerEntries.map(entry => ({
      id: entry.voucherId,
      customerId: entry.customerCode,
      customerName: entry.customerName,
      customerPhone: entry.customerPhone,
      customerPhoto: entry.customerPhoto,
      billNo: entry.billNo,
      jewelType: entry.jewelType,
      grossWeight: entry.grossWeight,
      netWeight: entry.netWeight,
      jewelryItems: entry.jewelryItems,
      finalLoanAmount: entry.finalLoanAmount,
      interestRate: entry.interestRate,
      interestAmount: entry.interestAmount,
      totalAmount: entry.totalAmount,
      repaidAmount: entry.repaidAmount,
      balanceAmount: entry.balanceAmount,
      disbursementDate: entry.disbursementDate,
      dueDate: entry.dueDate,
      lastPaymentDate: entry.lastPaymentDate,
      status: entry.status,
      daysOverdue: entry.daysOverdue,
      loanDuration: entry.loanDuration,
      paymentProgress: entry.paymentProgress,
      monthsPaid: entry.monthsPaid,
      closedDate: entry.closedDate
    }));

    const activeLoans = allLoans.filter(loan => loan.status === 'active' || loan.status === 'partial');
    const overdueLoans = allLoans.filter(loan => loan.status === 'overdue');
    const closedLoans = allLoans.filter(loan => loan.status === 'closed');

    // Fetch all customers
    const customers = await Customer.find().lean();

    console.log('Response summary:', {
      allLoans: allLoans.length,
      activeLoans: activeLoans.length,
      overdueLoans: overdueLoans.length,
      closedLoans: closedLoans.length,
      customers: customers.length
    });

    res.status(200).json({
      success: true,
      allLoans,
      activeLoans,
      overdueLoans,
      closedLoans,
      customers
    });
  } catch (err) {
    console.error('ERROR in getLedger:', {
      message: err.message,
      stack: err.stack,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({
      success: false,
      message: 'Failed to fetch ledger data',
      error: err.message
    });
  }
};